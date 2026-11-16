/**
 * The files the crowdsec container's watcher (docker/crowdsec/ingressi-sync.sh)
 * applies for the managed whitelists:
 *
 *   desired/whitelists/zz-ingressi-<id>.yaml  parser whitelists for s02-enrich
 *                                             ("zz-" sorts them after geoip-enrich,
 *                                             which sets the ASN and country)
 *   desired/allowlist.txt                     IP and CIDR entries, one per line,
 *                                             for the `ingressi` allowlist
 *   desired/generation                        written last
 */
import type { CrowdSecWhitelist } from "../models/crowdsec-whitelists";

/** A YAML double-quoted scalar (JSON strings are valid ones). */
function quote(value: string): string {
  return JSON.stringify(value);
}

/** A list of values as an expr array literal; values are digits or letters only (checked on input). */
function exprList(values: readonly string[]): string {
  return `[${values.map((value) => `'${value.replace(/[^0-9A-Za-z]/g, "")}'`).join(", ")}]`;
}

export function whitelistFileName(entry: Pick<CrowdSecWhitelist, "id">): string {
  return `zz-ingressi-${entry.id}.yaml`;
}

/** The CrowdSec expression an entry stands for, or null for IP and CIDR entries (which use ip/cidr lists). */
export function whitelistExpression(entry: Pick<CrowdSecWhitelist, "kind" | "values">): string | null {
  switch (entry.kind) {
    case "asn":
      return `evt.Meta.ASNNumber in ${exprList(entry.values)}`;
    case "country":
      return `evt.Meta.IsoCode in ${exprList(entry.values)}`;
    case "expression":
      return entry.values[0] ?? null;
    default:
      return null;
  }
}

/** The parser whitelist file of one entry. */
export function renderWhitelistYaml(entry: CrowdSecWhitelist): string {
  const lines = [
    `# Managed by Ingressi (CrowdSec whitelist #${entry.id}); changes made here are overwritten.`,
    `name: ${quote(`ingressi/wl-${entry.id}`)}`,
    `description: ${quote(`Ingressi whitelist: ${entry.name}`)}`,
    "whitelist:",
    `  reason: ${quote(entry.reason || entry.name)}`,
  ];
  const expression = whitelistExpression(entry);
  if (entry.kind === "ip" || entry.kind === "cidr") {
    lines.push(`  ${entry.kind}:`, ...entry.values.map((value) => `    - ${quote(value)}`));
  } else if (expression) {
    lines.push("  expression:", `    - ${quote(expression)}`);
  }
  return `${lines.join("\n")}\n`;
}

export type RenderedWhitelists = {
  /** File name in desired/whitelists → content. */
  files: Record<string, string>;
  allowlist: string;
};

export function renderWhitelists(entries: readonly CrowdSecWhitelist[]): RenderedWhitelists {
  const files: Record<string, string> = {};
  const allow = new Set<string>();
  for (const entry of entries) {
    if (!entry.enabled) continue;
    files[whitelistFileName(entry)] = renderWhitelistYaml(entry);
    if (entry.kind === "ip" || entry.kind === "cidr") for (const value of entry.values) allow.add(value);
  }
  return { files, allowlist: allow.size > 0 ? `${[...allow].join("\n")}\n` : "" };
}
