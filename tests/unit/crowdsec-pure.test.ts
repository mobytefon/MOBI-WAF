/**
 * The parts of the CrowdSec integration that need no database: per-host
 * modes, the settings checks, whitelist input and the YAML CrowdSec loads,
 * address ranges, alert filters and the Prometheus metrics it serves.
 */
import { describe, expect, it } from "vitest";
import { crowdSecAppliesToHost, crowdSecConfigForMode, crowdSecHostModeOf, validateCrowdSecHostConfig } from "@/src/lib/crowdsec/host-mode";
import { crowdSecSettingsError, normalizeCrowdSecSettings, parseCrowdSecDuration } from "@/src/lib/crowdsec/settings";
import { renderWhitelistYaml, renderWhitelists, whitelistExpression } from "@/src/lib/crowdsec/whitelist-render";
import { rangeContains } from "@/src/lib/crowdsec/ip";
import { parseCrowdSecMetrics, parseCrowdSecTarget } from "@/src/lib/crowdsec/lapi-client";
import { parseAlertQuery } from "@/src/lib/crowdsec/query";
import { summarizeAlerts, groupActiveDecisions } from "@/src/lib/crowdsec/dashboard";
import type { CrowdSecWhitelist } from "@/src/lib/models/crowdsec-whitelists";
import { normalizeWhitelistInput } from "@/src/lib/models/crowdsec-whitelists";

const SETTINGS = { enabled: true, apply_to_all_hosts: false, ticker_interval: "60s", lapi_timeout: "10s" };

describe("host modes", () => {
  it("maps stored configs to modes and back", () => {
    expect(crowdSecHostModeOf(null)).toBe("inherit");
    expect(crowdSecHostModeOf({})).toBe("inherit");
    expect(crowdSecHostModeOf({ enabled: true })).toBe("on");
    expect(crowdSecHostModeOf({ enabled: false })).toBe("off");
    expect(crowdSecConfigForMode("inherit")).toBeNull();
    expect(crowdSecConfigForMode("on")).toEqual({ enabled: true });
  });

  it("applies the master switch first, then the host, then apply to all hosts", () => {
    expect(crowdSecAppliesToHost({ ...SETTINGS, enabled: false }, { enabled: true })).toBe(false);
    expect(crowdSecAppliesToHost(SETTINGS, { enabled: true })).toBe(true);
    expect(crowdSecAppliesToHost(SETTINGS, null)).toBe(false);
    expect(crowdSecAppliesToHost({ ...SETTINGS, apply_to_all_hosts: true }, null)).toBe(true);
    expect(crowdSecAppliesToHost({ ...SETTINGS, apply_to_all_hosts: true }, { enabled: false })).toBe(false);
  });

  it("accepts only a boolean enabled", () => {
    expect(validateCrowdSecHostConfig({ enabled: true })).toEqual({ enabled: true });
    expect(validateCrowdSecHostConfig({})).toEqual({});
    expect(() => validateCrowdSecHostConfig({ enabled: 1 })).toThrow(/crowdsec\.enabled/);
    expect(() => validateCrowdSecHostConfig({ enabled: true, extra: 1 })).toThrow(/unknown field/);
    expect(() => validateCrowdSecHostConfig("on")).toThrow();
  });
});

describe("settings", () => {
  it("parses Go durations", () => {
    expect(parseCrowdSecDuration("60s")).toBe(60_000);
    expect(parseCrowdSecDuration("1m30s")).toBe(90_000);
    expect(parseCrowdSecDuration("500ms")).toBe(500);
    expect(parseCrowdSecDuration("1d")).toBeNull();
    expect(parseCrowdSecDuration("")).toBeNull();
  });

  it("fills defaults and replaces invalid values", () => {
    expect(normalizeCrowdSecSettings(null)).toEqual({ enabled: false, apply_to_all_hosts: false, ticker_interval: "60s", lapi_timeout: "10s" });
    expect(normalizeCrowdSecSettings({ enabled: true, ticker_interval: "1s" }).ticker_interval).toBe("60s");
  });

  it("checks a write", () => {
    expect(crowdSecSettingsError(SETTINGS)).toBeNull();
    expect(crowdSecSettingsError({ enabled: true, apply_to_all_hosts: false })).toBeNull();
    expect(crowdSecSettingsError({ ...SETTINGS, extra: true })).toMatch(/unknown field/);
    expect(crowdSecSettingsError({ ...SETTINGS, enabled: "yes" })).toMatch(/crowdsec\.enabled/);
    expect(crowdSecSettingsError({ ...SETTINGS, ticker_interval: "2h" })).toMatch(/ticker_interval/);
    expect(crowdSecSettingsError({ ...SETTINGS, lapi_timeout: "0s" })).toMatch(/lapi_timeout/);
  });
});

function entry(partial: Partial<CrowdSecWhitelist>): CrowdSecWhitelist {
  return { id: 1, name: "Test", kind: "ip", values: [], reason: "", enabled: true, createdBy: null, createdAt: "", updatedAt: "", ...partial };
}

describe("whitelists", () => {
  it("normalizes input by kind", () => {
    expect(normalizeWhitelistInput({ name: " ASNs ", kind: "asn", values: "AS131429, 45899\n18403" })).toMatchObject({ name: "ASNs", values: ["131429", "45899", "18403"] });
    expect(normalizeWhitelistInput({ name: "VN", kind: "country", values: ["vn"] }).values).toEqual(["VN"]);
    expect(normalizeWhitelistInput({ name: "LAN", kind: "cidr", values: ["10.0.0.0/8"] }).values).toEqual(["10.0.0.0/8"]);
    expect(() => normalizeWhitelistInput({ name: "x", kind: "ip", values: ["10.0.0.0/8"] })).toThrow(/not an IP address/);
    expect(() => normalizeWhitelistInput({ name: "x", kind: "cidr", values: ["10.0.0.1"] })).toThrow(/CIDR/);
    expect(() => normalizeWhitelistInput({ name: "x", kind: "asn", values: ["abc"] })).toThrow(/AS number/);
    expect(() => normalizeWhitelistInput({ name: "x", kind: "country", values: ["VNM"] })).toThrow(/country code/);
    expect(() => normalizeWhitelistInput({ name: "x", kind: "expression", values: "a\nb" })).toThrow(/one line/);
    expect(() => normalizeWhitelistInput({ name: "", kind: "ip", values: ["1.2.3.4"] })).toThrow(/Name/);
    expect(() => normalizeWhitelistInput({ name: "x", kind: "bogus" as never, values: [] })).toThrow(/Kind/);
  });

  it("renders the ASN whitelist as CrowdSec expects it in s02-enrich", () => {
    const yaml = renderWhitelistYaml(entry({ id: 7, name: "Trusted ASNs", kind: "asn", reason: "Trusted ASN", values: ["131429", "45899", "18403", "45903", "7552", "24086"] }));
    expect(yaml).toContain('name: "ingressi/wl-7"');
    expect(yaml).toContain('  reason: "Trusted ASN"');
    expect(yaml).toContain("  expression:\n    - \"evt.Meta.ASNNumber in ['131429', '45899', '18403', '45903', '7552', '24086']\"");
  });

  it("renders addresses, ranges, countries and expressions", () => {
    expect(renderWhitelistYaml(entry({ kind: "ip", values: ["192.0.2.1"] }))).toContain('  ip:\n    - "192.0.2.1"');
    expect(renderWhitelistYaml(entry({ kind: "cidr", values: ["10.0.0.0/8"] }))).toContain('  cidr:\n    - "10.0.0.0/8"');
    expect(whitelistExpression({ kind: "country", values: ["VN", "SG"] })).toBe("evt.Meta.IsoCode in ['VN', 'SG']");
    // Quotes inside an expression are escaped for YAML.
    expect(renderWhitelistYaml(entry({ kind: "expression", values: ['evt.Meta.http_path == "/healthz"'] }))).toContain('    - "evt.Meta.http_path == \\"/healthz\\""');
  });

  it("writes one file per enabled whitelist and the allowlist of its addresses and ranges", () => {
    const rendered = renderWhitelists([
      entry({ id: 1, kind: "ip", values: ["192.0.2.1"] }),
      entry({ id: 2, kind: "cidr", values: ["10.0.0.0/8", "192.0.2.1"] }),
      entry({ id: 3, kind: "asn", values: ["7552"] }),
      entry({ id: 4, kind: "ip", values: ["198.51.100.1"], enabled: false }),
    ]);
    expect(Object.keys(rendered.files).sort()).toEqual(["zz-ingressi-1.yaml", "zz-ingressi-2.yaml", "zz-ingressi-3.yaml"]);
    expect(rendered.allowlist).toBe("192.0.2.1\n10.0.0.0/8\n");
    expect(renderWhitelists([]).allowlist).toBe("");
  });
});

describe("address ranges", () => {
  it("tells whether a range contains an address or range", () => {
    expect(rangeContains("10.0.0.0/8", "10.1.2.3")).toBe(true);
    expect(rangeContains("10.0.0.0/8", "10.1.0.0/16")).toBe(true);
    expect(rangeContains("10.1.0.0/16", "10.0.0.0/8")).toBe(false);
    expect(rangeContains("10.0.0.0/8", "11.0.0.1")).toBe(false);
    expect(rangeContains("192.0.2.1", "192.0.2.1")).toBe(true);
    expect(rangeContains("2001:db8::/32", "2001:db8:1::5")).toBe(true);
    expect(rangeContains("2001:db8::/32", "2001:db9::1")).toBe(false);
    expect(rangeContains("10.0.0.0/8", "2001:db8::1")).toBe(false);
  });

  it("parses decision targets", () => {
    expect(parseCrowdSecTarget(" 192.0.2.1 ")).toEqual({ scope: "Ip", value: "192.0.2.1" });
    expect(parseCrowdSecTarget("192.0.2.0/24")).toEqual({ scope: "Range", value: "192.0.2.0/24" });
    expect(parseCrowdSecTarget("192.0.2.0/33")).toBeNull();
    expect(parseCrowdSecTarget("example.com")).toBeNull();
  });
});

describe("alert filters", () => {
  it("reads and checks URL parameters", () => {
    expect(parseAlertQuery(new URLSearchParams("since=24h&ip=192.0.2.0/24&scenario=crowdsecurity/http-probing&limit=50"))).toEqual({
      since: "24h",
      range: "192.0.2.0/24",
      scenario: "crowdsecurity/http-probing",
      limit: 50,
    });
    expect(() => parseAlertQuery(new URLSearchParams("since=yesterday"))).toThrow(/since/);
    expect(() => parseAlertQuery(new URLSearchParams("ip=nope"))).toThrow(/ip/);
    expect(() => parseAlertQuery(new URLSearchParams("scenario=a b"))).toThrow(/scenario/);
    expect(() => parseAlertQuery(new URLSearchParams("limit=0"))).toThrow(/limit/);
  });
});

describe("metrics and figures", () => {
  it("sums active decisions by origin", () => {
    const text = [
      "# HELP cs_active_decisions Number of active decisions.",
      'cs_active_decisions{action="ban",origin="CAPI",reason="http:scan"} 15000',
      'cs_active_decisions{action="ban",origin="CAPI",reason="ssh:bruteforce"} 5000',
      'cs_active_decisions{action="ban",origin="crowdsec",reason="crowdsecurity/http-probing"} 3',
      'cs_active_decisions{action="ban",origin="lists:firehol",reason="x"} 7',
    ].join("\n");
    const metrics = parseCrowdSecMetrics(text);
    expect(metrics.activeDecisionsByOrigin).toEqual({ CAPI: 20000, crowdsec: 3, "lists:firehol": 7 });
    expect(groupActiveDecisions(metrics.activeDecisionsByOrigin)).toMatchObject({ local: 3, community: 20000, lists: 7 });
  });

  it("counts alerts by scenario, source and time", () => {
    const now = Date.UTC(2026, 10, 16, 12, 30);
    const at = (hoursAgo: number) => new Date(now - hoursAgo * 3_600_000).toISOString();
    const alerts = [
      { id: 1, scenario: "crowdsecurity/http-probing", start_at: at(0), source: { ip: "192.0.2.1", cn: "vn", as_number: "7552", as_name: "Viettel" }, decisions: [{ id: 1 }] },
      { id: 2, scenario: "crowdsecurity/http-probing", start_at: at(1), source: { ip: "192.0.2.1", cn: "VN" } },
      { id: 3, scenario: "crowdsecurity/http-sensitive-files", start_at: at(30), source: { ip: "198.51.100.2", cn: "US" } },
    ] as never;
    const summary = summarizeAlerts(alerts, "24h", now);
    expect(summary.alerts).toBe(3);
    expect(summary.attackers).toBe(2);
    expect(summary.alertsWithDecision).toBe(1);
    expect(summary.topScenarios[0]).toMatchObject({ key: "crowdsecurity/http-probing", count: 2 });
    expect(summary.topCountries.map((row) => row.key)).toEqual(["VN", "US"]);
    expect(summary.topAs[0]).toMatchObject({ label: "AS7552", sub: "Viettel" });
    expect(summary.chart.buckets).toHaveLength(24);
    const probing = summary.chart.series.find((series) => series.key === "crowdsecurity/http-probing")!;
    expect(probing.values.at(-1)).toBe(1);
    expect(probing.values.at(-2)).toBe(1);
    // The alert of 30 hours ago is outside the chart.
    expect(summary.chart.series.reduce((sum, series) => sum + series.values.reduce((a, b) => a + b, 0), 0)).toBe(2);
  });
});
