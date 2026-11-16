/**
 * The dashboard's client of the CrowdSec Local API. It signs in as the
 * `ingressi-web` machine (watcher) to read alerts and to add and delete
 * decisions, and uses the bouncer key for decision lookups by address (which
 * include the community blocklist). Errors never carry the URL, credentials
 * or response bodies.
 */
import { isIP } from "node:net";
import { ApiClientError, ApiValidationError } from "../api-errors";
import { getCrowdSecEnvironment, type CrowdSecEnvironment } from "./config";

const REQUEST_TIMEOUT_MS = 10_000;
const MANUAL_SCENARIO = "manual/ingressi";

/**
 * CrowdSec could not be reached or refused the request. The message is
 * written here and safe to show; REST routes answer it with 502
 * (crowdsec/api.ts), dashboard actions show it.
 */
export class CrowdSecUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CrowdSecUnavailableError";
  }
}

// ── LAPI models (the fields the dashboard uses) ─────────────────────────────

export type CrowdSecSource = {
  scope?: string;
  value?: string;
  ip?: string;
  range?: string;
  as_number?: string;
  as_name?: string;
  cn?: string;
  latitude?: number;
  longitude?: number;
};

export type CrowdSecDecision = {
  id: number;
  origin: string;
  type: string;
  scope: string;
  value: string;
  duration: string;
  scenario: string;
  simulated?: boolean;
  until?: string;
};

export type CrowdSecEvent = { timestamp: string; meta: { key: string; value: string }[] };

export type CrowdSecAlert = {
  id: number;
  scenario: string;
  message?: string;
  events_count?: number;
  start_at?: string;
  stop_at?: string;
  created_at?: string;
  simulated?: boolean;
  remediation?: boolean;
  machine_id?: string;
  source: CrowdSecSource;
  decisions?: CrowdSecDecision[] | null;
  events?: CrowdSecEvent[] | null;
  meta?: { key: string; value: string }[] | null;
};

export type AlertQuery = {
  /** Go duration back from now, e.g. "24h". */
  since?: string;
  until?: string;
  ip?: string;
  range?: string;
  scenario?: string;
  origin?: string;
  hasActiveDecision?: boolean;
  limit?: number;
};

// ── Transport ───────────────────────────────────────────────────────────────

type Session = { token: string; expiresAt: number };
const SESSION_KEY = Symbol.for("ingressi.crowdsec.lapiSession");
const sessionHolder = globalThis as typeof globalThis & { [SESSION_KEY]?: Session | null };

function requireEnvironment(): CrowdSecEnvironment {
  const environment = getCrowdSecEnvironment();
  if (!environment) throw new CrowdSecUnavailableError("CrowdSec is not configured on this instance");
  return environment;
}

/** A fetch failure as a message that names no host, path or credential. */
function describeFailure(error: unknown): string {
  if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) return "the CrowdSec LAPI did not answer in time";
  const code = (error as { cause?: { code?: unknown } })?.cause?.code;
  return typeof code === "string" && /^[A-Z_]+$/.test(code) ? `the CrowdSec LAPI is unreachable (${code})` : "the CrowdSec LAPI is unreachable";
}

async function send(url: string, init: RequestInit, timeoutMs = REQUEST_TIMEOUT_MS): Promise<Response> {
  try {
    return await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
  } catch (error) {
    throw new CrowdSecUnavailableError(`CrowdSec request failed: ${describeFailure(error)}`);
  }
}

async function readJson<T>(response: Response): Promise<T> {
  const text = await response.text();
  if (!text) return null as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new CrowdSecUnavailableError("The CrowdSec LAPI sent an answer that is not JSON");
  }
}

async function login(environment: CrowdSecEnvironment): Promise<string> {
  if (!environment.machinePassword) {
    throw new CrowdSecUnavailableError("CROWDSEC_MACHINE_PASSWORD is not set, so the dashboard cannot sign in to CrowdSec");
  }
  const response = await send(`${environment.lapiUrl}/v1/watchers/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ machine_id: environment.machineId, password: environment.machinePassword, scenarios: [] }),
  });
  if (response.status === 401 || response.status === 403) {
    await response.body?.cancel();
    throw new CrowdSecUnavailableError("CrowdSec refused the dashboard's machine credentials");
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new CrowdSecUnavailableError(`CrowdSec sign-in failed (HTTP ${response.status})`);
  }
  const body = await readJson<{ token?: string; expire?: string }>(response);
  if (!body?.token) throw new CrowdSecUnavailableError("CrowdSec sign-in returned no token");
  const expire = body.expire ? Date.parse(body.expire) : NaN;
  // Renew a minute early; without an expiry, after 30 minutes.
  const expiresAt = Number.isFinite(expire) ? expire - 60_000 : Date.now() + 30 * 60_000;
  sessionHolder[SESSION_KEY] = { token: body.token, expiresAt };
  return body.token;
}

async function machineToken(environment: CrowdSecEnvironment, renew = false): Promise<string> {
  const session = sessionHolder[SESSION_KEY];
  if (!renew && session && session.expiresAt > Date.now()) return session.token;
  return await login(environment);
}

/** A request as the machine; signs in again once when the token is refused. */
async function machineRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const environment = requireEnvironment();
  let renew = false;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const token = await machineToken(environment, renew);
    const response = await send(`${environment.lapiUrl}${path}`, {
      ...init,
      headers: { ...(init.body ? { "Content-Type": "application/json" } : {}), ...init.headers, Authorization: `Bearer ${token}` },
    });
    if (response.status === 401 && attempt === 0) {
      await response.body?.cancel();
      sessionHolder[SESSION_KEY] = null;
      renew = true;
      continue;
    }
    if (response.status === 404) {
      await response.body?.cancel();
      throw new ApiClientError("Not found in CrowdSec", 404);
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new CrowdSecUnavailableError(`CrowdSec answered HTTP ${response.status}`);
    }
    return await readJson<T>(response);
  }
  throw new CrowdSecUnavailableError("CrowdSec refused the dashboard's machine credentials");
}

async function bouncerRequest<T>(path: string): Promise<T> {
  const environment = requireEnvironment();
  const response = await send(`${environment.lapiUrl}${path}`, { headers: { "X-Api-Key": environment.bouncerKey } });
  if (!response.ok) {
    await response.body?.cancel();
    throw new CrowdSecUnavailableError(`CrowdSec answered HTTP ${response.status} to the bouncer key`);
  }
  return await readJson<T>(response);
}

/** Forgets the machine session (tests, credential rotation). */
export function resetCrowdSecSession(): void {
  sessionHolder[SESSION_KEY] = null;
}

// ── Short-lived cache of reads ──────────────────────────────────────────────

const CACHE_TTL_MS = 15_000;
const CACHE_KEY = Symbol.for("ingressi.crowdsec.readCache");
const cacheHolder = globalThis as typeof globalThis & { [CACHE_KEY]?: Map<string, { at: number; value: Promise<unknown> }> };

function cached<T>(key: string, load: () => Promise<T>): Promise<T> {
  const cache = (cacheHolder[CACHE_KEY] ??= new Map());
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value as Promise<T>;
  const value = load();
  cache.set(key, { at: Date.now(), value });
  value.catch(() => cache.delete(key));
  if (cache.size > 200) cache.delete(cache.keys().next().value!);
  return value;
}

/** Drops cached reads, after a change (a decision added or deleted). */
export function clearCrowdSecReadCache(): void {
  cacheHolder[CACHE_KEY]?.clear();
}

// ── Input checks ────────────────────────────────────────────────────────────

const DURATION = /^(?:\d+(?:ms|s|m|h))+$/;

export function isCrowdSecDuration(value: string): boolean {
  return DURATION.test(value);
}

/** An address or a CIDR range in canonical text, or null when it is neither. */
export function parseCrowdSecTarget(value: string): { scope: "Ip" | "Range"; value: string } | null {
  const text = value.trim();
  if (isIP(text)) return { scope: "Ip", value: text };
  const match = /^([^/]+)\/(\d{1,3})$/.exec(text);
  if (!match) return null;
  const family = isIP(match[1]);
  const bits = Number(match[2]);
  if (!family || bits > (family === 4 ? 32 : 128)) return null;
  return { scope: "Range", value: `${match[1]}/${bits}` };
}

// ── Reads ───────────────────────────────────────────────────────────────────

function alertQueryString(query: AlertQuery): string {
  const params = new URLSearchParams();
  if (query.since) params.set("since", query.since);
  if (query.until) params.set("until", query.until);
  if (query.ip) params.set("ip", query.ip);
  if (query.range) params.set("range", query.range);
  if (query.scenario) params.set("scenario", query.scenario);
  if (query.origin) params.set("origin", query.origin);
  if (query.hasActiveDecision !== undefined) params.set("has_active_decision", String(query.hasActiveDecision));
  params.set("limit", String(Math.min(Math.max(query.limit ?? 100, 1), 10_000)));
  // The community blocklist is one alert with every address of the list: never listed here.
  params.set("include_capi", "false");
  return params.toString();
}

export async function listAlerts(query: AlertQuery = {}): Promise<CrowdSecAlert[]> {
  const qs = alertQueryString(query);
  return await cached(`alerts?${qs}`, async () => (await machineRequest<CrowdSecAlert[] | null>(`/v1/alerts?${qs}`)) ?? []);
}

export async function getAlert(id: number): Promise<CrowdSecAlert> {
  if (!Number.isSafeInteger(id) || id < 1) throw new ApiValidationError("Alert id must be a positive integer");
  return await machineRequest<CrowdSecAlert>(`/v1/alerts/${id}`);
}

/** Active decisions for one address, community blocklist included (bouncer API). */
export async function decisionsForAddress(address: string): Promise<CrowdSecDecision[]> {
  const target = parseCrowdSecTarget(address);
  if (!target) throw new ApiValidationError("Enter an IP address or a CIDR range");
  const param = target.scope === "Ip" ? `ip=${encodeURIComponent(target.value)}` : `range=${encodeURIComponent(target.value)}&contains=true`;
  return (await bouncerRequest<CrowdSecDecision[] | null>(`/v1/decisions?${param}`)) ?? [];
}

/** Whether the LAPI answers the dashboard's machine credentials. */
export async function checkLapi(): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await machineRequest<unknown>("/v1/heartbeat");
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "CrowdSec is unreachable" };
  }
}

// ── Changes ─────────────────────────────────────────────────────────────────

export type NewDecision = {
  target: string;
  type: "ban" | "captcha" | "throttle";
  duration: string;
  reason: string;
};

/** Adds a decision the way `cscli decisions add` does: an alert carrying it. Returns the alert id. */
export async function addDecision(input: NewDecision): Promise<number | null> {
  const target = parseCrowdSecTarget(input.target);
  if (!target) throw new ApiValidationError("Enter an IP address or a CIDR range");
  if (!["ban", "captcha", "throttle"].includes(input.type)) throw new ApiValidationError("Decision type must be ban, captcha or throttle");
  if (!isCrowdSecDuration(input.duration)) throw new ApiValidationError('Duration must look like "4h", "30m" or "168h"');
  const reason = input.reason.trim().slice(0, 500) || "Manual decision from the dashboard";
  const now = new Date().toISOString();
  const source = target.scope === "Ip"
    ? { scope: "Ip", value: target.value, ip: target.value }
    : { scope: "Range", value: target.value, range: target.value };
  const ids = await machineRequest<string[] | null>("/v1/alerts", {
    method: "POST",
    body: JSON.stringify([
      {
        scenario: MANUAL_SCENARIO,
        scenario_hash: "",
        scenario_version: "",
        message: reason,
        events_count: 1,
        start_at: now,
        stop_at: now,
        capacity: 0,
        leakspeed: "0",
        simulated: false,
        events: [],
        source,
        decisions: [
          { duration: input.duration, origin: "cscli", scenario: reason, scope: target.scope, type: input.type, value: target.value },
        ],
      },
    ]),
  });
  clearCrowdSecReadCache();
  const id = Number(ids?.[0]);
  return Number.isSafeInteger(id) ? id : null;
}

export async function deleteDecision(id: number): Promise<number> {
  if (!Number.isSafeInteger(id) || id < 1) throw new ApiValidationError("Decision id must be a positive integer");
  const body = await machineRequest<{ nbDeleted?: string | number } | null>(`/v1/decisions/${id}`, { method: "DELETE" });
  clearCrowdSecReadCache();
  return Number(body?.nbDeleted ?? 0);
}

/** Deletes every decision for one address or range. Returns how many were deleted. */
export async function deleteDecisionsFor(address: string): Promise<number> {
  const target = parseCrowdSecTarget(address);
  if (!target) throw new ApiValidationError("Enter an IP address or a CIDR range");
  const param = target.scope === "Ip" ? `ip=${encodeURIComponent(target.value)}` : `range=${encodeURIComponent(target.value)}`;
  const body = await machineRequest<{ nbDeleted?: string | number } | null>(`/v1/decisions?${param}`, { method: "DELETE" });
  clearCrowdSecReadCache();
  return Number(body?.nbDeleted ?? 0);
}

// ── Prometheus metrics ──────────────────────────────────────────────────────

export type CrowdSecMetrics = {
  /** Active decisions by origin (crowdsec, cscli, CAPI, lists:<name>). */
  activeDecisionsByOrigin: Record<string, number>;
};

/** Parses the Prometheus text CrowdSec serves (only the series the dashboard shows). */
export function parseCrowdSecMetrics(text: string): CrowdSecMetrics {
  const activeDecisionsByOrigin: Record<string, number> = {};
  for (const line of text.split("\n")) {
    const match = /^cs_active_decisions\{([^}]*)\}\s+([0-9.eE+-]+)/.exec(line);
    if (!match) continue;
    const origin = /(?:^|,)origin="([^"]*)"/.exec(match[1])?.[1] ?? "unknown";
    const value = Number(match[2]);
    if (Number.isFinite(value)) activeDecisionsByOrigin[origin] = (activeDecisionsByOrigin[origin] ?? 0) + value;
  }
  return { activeDecisionsByOrigin };
}

export async function fetchCrowdSecMetrics(): Promise<CrowdSecMetrics | null> {
  const environment = getCrowdSecEnvironment();
  if (!environment?.metricsUrl) return null;
  return await cached("metrics", async () => {
    const response = await send(environment.metricsUrl!, {}, 5_000);
    if (!response.ok) {
      await response.body?.cancel();
      throw new CrowdSecUnavailableError(`CrowdSec metrics answered HTTP ${response.status}`);
    }
    return parseCrowdSecMetrics(await response.text());
  });
}
