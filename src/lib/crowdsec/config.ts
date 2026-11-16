/**
 * How this process reaches CrowdSec, read from the environment that
 * docker-compose.crowdsec.yml sets on the web service. Without a LAPI URL and
 * a bouncer key the CrowdSec integration is off on this instance: no
 * `crowdsec` app or handler is emitted and the dashboard pages explain how
 * to turn it on. Read on every call, so tests can set the variables.
 */

export const CROWDSEC_DEFAULT_LAPI_URL = "http://crowdsec:8080";
export const CROWDSEC_DEFAULT_MACHINE_ID = "ingressi-web";

export type CrowdSecEnvironment = {
  /** CrowdSec Local API base URL, without a trailing slash. */
  lapiUrl: string;
  /** API key of the Caddy bouncer (registered in CrowdSec as BOUNCER_KEY_ingressi_caddy). */
  bouncerKey: string;
  /** Prometheus endpoint of CrowdSec, or null when not configured. */
  metricsUrl: string | null;
  /** Machine (watcher) credentials the dashboard reads alerts and manages decisions with. */
  machineId: string;
  machinePassword: string | null;
  /** Directory shared with the crowdsec container for managed whitelists, or null. */
  managedDir: string | null;
};

function env(name: string): string | null {
  const value = process.env[name]?.trim();
  return value ? value : null;
}

function withoutTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

/** The CrowdSec environment of this process, or null when the integration is not configured. */
export function getCrowdSecEnvironment(): CrowdSecEnvironment | null {
  const bouncerKey = env("CROWDSEC_BOUNCER_KEY");
  if (!bouncerKey) return null;
  const lapiUrl = withoutTrailingSlash(env("CROWDSEC_LAPI_URL") ?? CROWDSEC_DEFAULT_LAPI_URL);
  const metricsUrl = env("CROWDSEC_METRICS_URL");
  return {
    lapiUrl,
    bouncerKey,
    metricsUrl,
    machineId: env("CROWDSEC_MACHINE_ID") ?? CROWDSEC_DEFAULT_MACHINE_ID,
    machinePassword: env("CROWDSEC_MACHINE_PASSWORD"),
    managedDir: env("CROWDSEC_MANAGED_DIR"),
  };
}

/** Whether the CrowdSec integration is configured for this process. */
export function isCrowdSecConfigured(): boolean {
  return getCrowdSecEnvironment() !== null;
}
