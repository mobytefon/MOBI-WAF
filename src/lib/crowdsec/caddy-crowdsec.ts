/**
 * The CrowdSec bouncer in the Caddy configuration (the
 * github.com/hslatman/caddy-crowdsec-bouncer `crowdsec` app and its
 * `http.handlers.crowdsec` handler). The app pulls decisions from the LAPI in
 * stream mode, community blocklist included, and keeps them in memory; the
 * handler runs first on every route of a host that uses CrowdSec and blocks
 * client addresses with a decision. The app is emitted only when some host
 * uses the handler, since the handler needs it.
 */
import { getCrowdSecEnvironment, type CrowdSecEnvironment } from "./config";
import { crowdSecAppliesToHost, type CrowdSecHostConfig } from "./host-mode";
import { getCrowdSecSettings, type CrowdSecSettings } from "./settings";

export type CrowdSecCaddyContext = {
  settings: CrowdSecSettings;
  app: Record<string, unknown>;
  /** Filled while the routes are built: the hosts whose routes got the handler. */
  hostIds: Set<number>;
};

export function buildCrowdSecApp(settings: CrowdSecSettings, environment: CrowdSecEnvironment): Record<string, unknown> {
  return {
    api_url: `${environment.lapiUrl}/`,
    api_key: environment.bouncerKey,
    ticker_interval: settings.ticker_interval,
    lapi_timeout: settings.lapi_timeout,
    // Stream mode: decisions are kept in memory, so a lookup costs no LAPI
    // request. The bouncer pulls the community blocklist too.
    enable_streaming: true,
    // An unreachable LAPI must not keep Caddy from starting.
    enable_hard_fails: false,
    enable_caddy_metrics: true,
  };
}

export function buildCrowdSecHandler(): Record<string, unknown> {
  return { handler: "crowdsec" };
}

/** The bouncer's settings for this build, or null when no host can use it here. */
export async function loadCrowdSecCaddyContext(): Promise<CrowdSecCaddyContext | null> {
  const environment = getCrowdSecEnvironment();
  if (!environment) return null;
  const settings = await getCrowdSecSettings();
  if (!settings.enabled) return null;
  return { settings, app: buildCrowdSecApp(settings, environment), hostIds: new Set() };
}

/**
 * Puts the bouncer in front of a host's handlers, when the host uses it, and
 * notes the host. Each list is changed in place; the bouncer goes first so
 * blocked addresses cost no WAF inspection, rate limiting or upstream work.
 */
export function prependCrowdSecHandler(
  context: CrowdSecCaddyContext | null | undefined,
  hostId: number,
  config: CrowdSecHostConfig | null | undefined,
  ...handlerLists: Record<string, unknown>[][]
): void {
  if (!context || !crowdSecAppliesToHost(context.settings, config)) return;
  for (const list of handlerLists) list.unshift(buildCrowdSecHandler());
  context.hostIds.add(hostId);
}

/** The `apps` entry for the bouncer: present only when some host's routes use the handler. */
export function crowdSecAppsEntry(context: CrowdSecCaddyContext | null | undefined): { crowdsec?: Record<string, unknown> } {
  return context && context.hostIds.size > 0 ? { crowdsec: context.app } : {};
}
