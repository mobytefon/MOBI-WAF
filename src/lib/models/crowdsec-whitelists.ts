/**
 * CrowdSec whitelists managed from the dashboard. Each one becomes a parser
 * whitelist (src/lib/crowdsec/whitelist-render.ts) that CrowdSec applies in
 * its s02-enrich stage, so matching events raise no alert; IP and CIDR
 * entries also go to the `ingressi` allowlist, which keeps the community
 * blocklist and other lists from banning them. They are stored in the
 * settings table (one row, small), with a generation that goes up on every
 * change; src/lib/crowdsec/managed-sync.ts hands each generation to the
 * crowdsec container.
 */
import { appDb } from "../db";
import { logAuditEvent } from "../audit";
import { ApiClientError, ApiValidationError } from "../api-errors";
import { getSetting, setSetting } from "../settings";
import { parseAddressOrRange, rangeContains } from "../crowdsec/ip";
import { withSettingsUpdateLock } from "../settings-update-lock";

export const CROWDSEC_WHITELISTS_KEY = "crowdsec_whitelists";

export const WHITELIST_KINDS = ["ip", "cidr", "asn", "country", "expression"] as const;
export type WhitelistKind = (typeof WHITELIST_KINDS)[number];

export type CrowdSecWhitelist = {
  id: number;
  name: string;
  kind: WhitelistKind;
  /** Addresses, ranges, AS numbers or country codes; one CrowdSec expression for "expression". */
  values: string[];
  reason: string;
  enabled: boolean;
  createdBy: number | null;
  createdAt: string;
  updatedAt: string;
};

export type CrowdSecWhitelistInput = {
  name: string;
  kind: WhitelistKind;
  values: string[] | string;
  reason?: string;
  enabled?: boolean;
};

type Stored = { nextId: number; generation: number; entries: CrowdSecWhitelist[] };

const MAX_ENTRIES = 500;
const MAX_VALUES = 1_000;
const MAX_EXPRESSION = 2_000;

const EMPTY: Stored = { nextId: 1, generation: 0, entries: [] };

async function readStored(): Promise<Stored> {
  const stored = await getSetting<Stored>(CROWDSEC_WHITELISTS_KEY);
  if (!stored || !Array.isArray(stored.entries)) return { ...EMPTY, entries: [] };
  return {
    nextId: Number.isSafeInteger(stored.nextId) ? stored.nextId : 1,
    generation: Number.isSafeInteger(stored.generation) ? stored.generation : 0,
    entries: stored.entries,
  };
}

export async function listCrowdSecWhitelists(): Promise<CrowdSecWhitelist[]> {
  return (await readStored()).entries;
}

/** The generation of the whitelists: it goes up with every change. */
export async function getCrowdSecWhitelistGeneration(): Promise<number> {
  return (await readStored()).generation;
}

/** The whitelists and their generation, read together. */
export async function readCrowdSecWhitelistState(): Promise<{ generation: number; entries: CrowdSecWhitelist[] }> {
  const stored = await readStored();
  return { generation: stored.generation, entries: stored.entries };
}

/** Whether text has a control character (a line break, a tab, NUL…). */
function hasControlCharacters(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) if (text.charCodeAt(i) < 0x20) return true;
  return false;
}

function splitValues(values: string[] | string): string[] {
  const list = Array.isArray(values) ? values : values.split(/[\s,]+/);
  return [...new Set(list.map((value) => String(value).trim()).filter(Boolean))];
}

/** Checks and normalizes an input; throws ApiValidationError with a message for the user. */
export function normalizeWhitelistInput(input: CrowdSecWhitelistInput): Omit<CrowdSecWhitelist, "id" | "createdBy" | "createdAt" | "updatedAt"> {
  if (typeof input !== "object" || input === null) throw new ApiValidationError("Whitelist must be an object");
  const name = typeof input.name === "string" ? input.name.trim() : "";
  if (!name || name.length > 100 || hasControlCharacters(name)) throw new ApiValidationError("Name must be 1 to 100 characters");
  if (!(WHITELIST_KINDS as readonly unknown[]).includes(input.kind)) {
    throw new ApiValidationError(`Kind must be one of ${WHITELIST_KINDS.join(", ")}`);
  }
  const reason = typeof input.reason === "string" ? input.reason.trim() : "";
  if (reason.length > 300 || hasControlCharacters(reason)) throw new ApiValidationError("Reason must be at most 300 characters on one line");
  if (input.enabled !== undefined && typeof input.enabled !== "boolean") throw new ApiValidationError("enabled must be true or false");

  let values: string[];
  if (input.kind === "expression") {
    const expression = (Array.isArray(input.values) ? input.values.join(" ") : String(input.values ?? "")).trim();
    if (!expression) throw new ApiValidationError("Enter a CrowdSec expression, e.g. evt.Meta.ASNNumber in ['7552']");
    if (expression.length > MAX_EXPRESSION || hasControlCharacters(expression)) {
      throw new ApiValidationError(`The expression must be one line of at most ${MAX_EXPRESSION} characters`);
    }
    values = [expression];
  } else {
    values = splitValues(input.values ?? []);
    if (values.length === 0) throw new ApiValidationError("Add at least one value");
    if (values.length > MAX_VALUES) throw new ApiValidationError(`At most ${MAX_VALUES} values per whitelist`);
    for (const value of values) {
      const problem = valueProblem(input.kind, value);
      if (problem) throw new ApiValidationError(problem);
    }
    if (input.kind === "country") values = values.map((value) => value.toUpperCase());
    if (input.kind === "asn") values = values.map((value) => value.replace(/^AS/i, ""));
  }
  return { name, kind: input.kind, values, reason, enabled: input.enabled ?? true };
}

function valueProblem(kind: WhitelistKind, value: string): string | null {
  switch (kind) {
    case "ip": {
      const parsed = parseAddressOrRange(value);
      return parsed && !value.includes("/") ? null : `${value} is not an IP address`;
    }
    case "cidr":
      return value.includes("/") && parseAddressOrRange(value) ? null : `${value} is not a CIDR range (such as 10.0.0.0/8)`;
    case "asn": {
      const digits = value.replace(/^AS/i, "");
      return /^\d{1,10}$/.test(digits) && Number(digits) <= 4_294_967_295 ? null : `${value} is not an AS number`;
    }
    case "country":
      return /^[A-Za-z]{2}$/.test(value) ? null : `${value} is not a two-letter country code (ISO 3166-1)`;
    default:
      return null;
  }
}

/** Runs a change under the settings lock, in a transaction, with the generation raised. */
async function change<T>(apply: (stored: Stored, now: string) => T): Promise<T> {
  return await withSettingsUpdateLock(async () =>
    await appDb.transaction(async () => {
      const stored = await readStored();
      const now = new Date().toISOString();
      const result = apply(stored, now);
      stored.generation += 1;
      await setSetting(CROWDSEC_WHITELISTS_KEY, stored);
      return result;
    })
  );
}

export async function createCrowdSecWhitelist(input: CrowdSecWhitelistInput, actorUserId: number | null): Promise<CrowdSecWhitelist> {
  const normalized = normalizeWhitelistInput(input);
  const entry = await change((stored, now) => {
    if (stored.entries.length >= MAX_ENTRIES) throw new ApiValidationError(`At most ${MAX_ENTRIES} whitelists`);
    const created: CrowdSecWhitelist = { id: stored.nextId, ...normalized, createdBy: actorUserId, createdAt: now, updatedAt: now };
    stored.nextId += 1;
    stored.entries.push(created);
    return created;
  });
  await logAuditEvent({ userId: actorUserId, action: "create", entityType: "crowdsec_whitelist", entityId: entry.id, summary: `Created CrowdSec whitelist "${entry.name}"`, data: entry });
  return entry;
}

export async function updateCrowdSecWhitelist(id: number, input: CrowdSecWhitelistInput, actorUserId: number | null): Promise<CrowdSecWhitelist> {
  const normalized = normalizeWhitelistInput(input);
  const entry = await change((stored, now) => {
    const index = stored.entries.findIndex((item) => item.id === id);
    if (index < 0) throw new ApiClientError("Whitelist not found", 404);
    const updated = { ...stored.entries[index], ...normalized, updatedAt: now };
    stored.entries[index] = updated;
    return updated;
  });
  await logAuditEvent({ userId: actorUserId, action: "update", entityType: "crowdsec_whitelist", entityId: id, summary: `Updated CrowdSec whitelist "${entry.name}"`, data: entry });
  return entry;
}

export async function deleteCrowdSecWhitelist(id: number, actorUserId: number | null): Promise<void> {
  const removed = await change((stored) => {
    const index = stored.entries.findIndex((item) => item.id === id);
    if (index < 0) throw new ApiClientError("Whitelist not found", 404);
    return stored.entries.splice(index, 1)[0];
  });
  await logAuditEvent({ userId: actorUserId, action: "delete", entityType: "crowdsec_whitelist", entityId: id, summary: `Deleted CrowdSec whitelist "${removed.name}"`, data: removed });
}

/** Raises the generation without a change, so the whitelists are handed to CrowdSec again. */
export async function reapplyCrowdSecWhitelists(actorUserId: number | null): Promise<number> {
  const generation = await change((stored) => stored.generation + 1);
  await logAuditEvent({ userId: actorUserId, action: "update", entityType: "crowdsec_whitelist", summary: "Applied the CrowdSec whitelists again" });
  return generation;
}

/** The enabled IP and CIDR whitelists that cover an address or range. */
export async function whitelistsCovering(target: string): Promise<CrowdSecWhitelist[]> {
  const entries = await listCrowdSecWhitelists();
  return entries.filter(
    (entry) => entry.enabled && (entry.kind === "ip" || entry.kind === "cidr") && entry.values.some((value) => rangeContains(value, target.trim()))
  );
}
