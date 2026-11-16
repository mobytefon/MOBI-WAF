/**
 * The CrowdSec bouncer in the generated Caddy configuration: the `crowdsec`
 * handler runs first on every route of a host that uses it (before rate
 * limiting and the WAF), the `crowdsec` app is emitted only when some host
 * uses the handler, and nothing is emitted without CROWDSEC_BOUNCER_KEY or
 * with CrowdSec turned off. Hosts inherit "apply to all hosts", or turn it
 * on or off for themselves.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TestDb } from "../helpers/db";

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock("../../src/lib/db", async () => {
  const { createTestDb } = await import("../helpers/db");
  ctx.db = createTestDb();
  return (await import("../helpers/db-module")).mockDbModule(() => ctx.db);
});

vi.mock("../../src/lib/caddy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/lib/caddy")>();
  return { ...actual, applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }) };
});

vi.mock("../../src/lib/audit", () => ({ logAuditEvent: vi.fn() }));

import { createProxyHost, getProxyHost, updateProxyHost, type ProxyHostInput } from "../../src/lib/models/proxy-hosts";
import { saveWafSettings } from "../../src/lib/settings";
import { saveCrowdSecSettings, type CrowdSecSettings } from "../../src/lib/crowdsec/settings";
import { buildCaddyDocument } from "../../src/lib/caddy";
import * as schema from "../../src/lib/db/schema";

type Handler = Record<string, any>;
type Doc = Awaited<ReturnType<typeof buildCaddyDocument>>;

const ON: CrowdSecSettings = { enabled: true, apply_to_all_hosts: false, ticker_interval: "15s", lapi_timeout: "5s" };

function collectHandleArrays(node: unknown, out: Handler[][] = []): Handler[][] {
  if (Array.isArray(node)) for (const item of node) collectHandleArrays(item, out);
  else if (node && typeof node === "object") {
    const obj = node as Record<string, unknown>;
    if (Array.isArray(obj.handle)) out.push(obj.handle as Handler[]);
    for (const value of Object.values(obj)) collectHandleArrays(value, out);
  }
  return out;
}

/** The handle arrays of the routes that proxy to `dial`. */
function upstreamRoutes(doc: Doc, dial: string): Handler[][] {
  const routes = (doc.apps as any).http.servers.ingressi.routes;
  return collectHandleArrays(routes).filter((handlers) =>
    handlers.some((h) => h.handler === "reverse_proxy" && (h.upstreams ?? []).some((u: { dial?: string }) => u.dial === dial))
  );
}

const isCrowdSec = (h: Handler) => h?.handler === "crowdsec";

async function host(name: string, dial: string, extra: Partial<ProxyHostInput> = {}) {
  return await createProxyHost({ name, domains: [`${name}.example.com`], upstreams: [dial], ...extra }, 1);
}

beforeEach(async () => {
  process.env.CROWDSEC_BOUNCER_KEY = "test-bouncer-key";
  process.env.CROWDSEC_LAPI_URL = "http://crowdsec:8080/";
  await ctx.db.delete(schema.proxyHosts);
  await ctx.db.delete(schema.settings);
  await ctx.db.delete(schema.users);
  const now = new Date().toISOString();
  await ctx.db.insert(schema.users).values({
    id: 1,
    email: "admin@example.com",
    name: "Admin",
    role: "admin",
    provider: "credentials",
    subject: "admin",
    status: "active",
    createdAt: now,
    updatedAt: now,
  });
});

afterEach(() => {
  delete process.env.CROWDSEC_BOUNCER_KEY;
  delete process.env.CROWDSEC_LAPI_URL;
  vi.restoreAllMocks();
});

describe("CrowdSec in the Caddy configuration", () => {
  it("emits nothing while CrowdSec is off, or not configured", async () => {
    await host("on", "10.0.0.1:80", { crowdsec: { enabled: true } });
    expect(JSON.stringify(await buildCaddyDocument())).not.toContain("crowdsec");

    await saveCrowdSecSettings(ON);
    delete process.env.CROWDSEC_BOUNCER_KEY;
    expect(JSON.stringify(await buildCaddyDocument())).not.toContain("crowdsec");
  });

  it("puts the handler first on a host turned on, in front of rate limiting and the WAF, with the app", async () => {
    await saveCrowdSecSettings(ON);
    await saveWafSettings({ enabled: true, mode: "On", load_owasp_crs: false, custom_directives: "" });
    await host("on", "10.0.0.1:80", {
      crowdsec: { enabled: true },
      locationRules: [{ path: "/api/*", upstreams: ["10.0.0.9:80"] }],
      rateLimit: { rules: [{ path: "/login", methods: ["POST"], key: "client_ip", events: 5, window: "1m" }] },
    });
    await host("inherit", "10.0.0.2:80");
    await host("off", "10.0.0.3:80", { crowdsec: { enabled: false } });

    const doc = await buildCaddyDocument();
    const onRoutes = [...upstreamRoutes(doc, "10.0.0.1:80"), ...upstreamRoutes(doc, "10.0.0.9:80")];
    expect(onRoutes.length).toBeGreaterThanOrEqual(2);
    for (const handlers of onRoutes) {
      expect(handlers.findIndex(isCrowdSec)).toBe(0);
      expect(handlers.filter(isCrowdSec)).toHaveLength(1);
      // The rate limiter (an invoke) and the WAF come after it.
      expect(handlers.findIndex((h) => h.handler === "invoke")).toBeGreaterThan(0);
      expect(handlers.findIndex((h) => JSON.stringify(h).includes('"handler":"waf"'))).toBeGreaterThan(0);
    }
    for (const dial of ["10.0.0.2:80", "10.0.0.3:80"]) {
      for (const handlers of upstreamRoutes(doc, dial)) expect(handlers.some(isCrowdSec)).toBe(false);
    }
    expect((doc.apps as any).crowdsec).toEqual({
      api_url: "http://crowdsec:8080/",
      api_key: "test-bouncer-key",
      ticker_interval: "15s",
      lapi_timeout: "5s",
      enable_streaming: true,
      enable_hard_fails: false,
      enable_caddy_metrics: true,
    });
  });

  it("covers inheriting hosts with apply to all hosts, but not hosts turned off", async () => {
    await saveCrowdSecSettings({ ...ON, apply_to_all_hosts: true });
    await host("inherit", "10.0.0.2:80");
    await host("off", "10.0.0.3:80", { crowdsec: { enabled: false } });
    const doc = await buildCaddyDocument();
    for (const handlers of upstreamRoutes(doc, "10.0.0.2:80")) expect(handlers.findIndex(isCrowdSec)).toBe(0);
    for (const handlers of upstreamRoutes(doc, "10.0.0.3:80")) expect(handlers.some(isCrowdSec)).toBe(false);
  });

  it("leaves the app out when no host uses the handler", async () => {
    await saveCrowdSecSettings(ON);
    await host("inherit", "10.0.0.2:80");
    expect((await buildCaddyDocument()).apps).not.toHaveProperty("crowdsec");
  });
});

describe("a host's CrowdSec setting", () => {
  it("is stored, read back, and cleared with null", async () => {
    const created = await host("app", "10.0.0.4:80", { crowdsec: { enabled: true } });
    expect((await getProxyHost(created.id))?.crowdsec).toEqual({ enabled: true });
    await updateProxyHost(created.id, { crowdsec: { enabled: false } }, 1);
    expect((await getProxyHost(created.id))?.crowdsec).toEqual({ enabled: false });
    await updateProxyHost(created.id, { crowdsec: null }, 1);
    expect((await getProxyHost(created.id))?.crowdsec ?? null).toBeNull();
  });

  it("rejects anything but a boolean enabled", async () => {
    await expect(host("bad", "10.0.0.5:80", { crowdsec: { enabled: "yes" } as never })).rejects.toThrow(/crowdsec\.enabled/);
    await expect(host("bad2", "10.0.0.6:80", { crowdsec: { mode: "on" } as never })).rejects.toThrow(/unknown field/);
  });
});
