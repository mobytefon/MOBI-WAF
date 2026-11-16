/**
 * The dashboard's CrowdSec LAPI client: it signs in as its machine, signs in
 * again once when the token is refused, sends manual decisions as an alert
 * the way cscli does, and never puts the LAPI address or credentials in its
 * errors.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { addDecision, clearCrowdSecReadCache, CrowdSecUnavailableError, listAlerts, resetCrowdSecSession } from "@/src/lib/crowdsec/lapi-client";

const fetchMock = vi.fn();

function reply(status: number, body: unknown) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  process.env.CROWDSEC_BOUNCER_KEY = "bouncer-key";
  process.env.CROWDSEC_LAPI_URL = "http://crowdsec.internal:8080";
  process.env.CROWDSEC_MACHINE_PASSWORD = "machine-secret";
  resetCrowdSecSession();
  clearCrowdSecReadCache();
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  for (const name of ["CROWDSEC_BOUNCER_KEY", "CROWDSEC_LAPI_URL", "CROWDSEC_MACHINE_PASSWORD"]) delete process.env[name];
});

describe("CrowdSec LAPI client", () => {
  it("signs in as the machine and reads alerts without the community blocklist", async () => {
    fetchMock
      .mockResolvedValueOnce(reply(200, { token: "jwt-1", expire: new Date(Date.now() + 3_600_000).toISOString() }))
      .mockResolvedValueOnce(reply(200, [{ id: 1, scenario: "crowdsecurity/http-probing", source: { ip: "192.0.2.1" } }]));
    const alerts = await listAlerts({ since: "24h" });
    expect(alerts).toHaveLength(1);
    const [loginUrl, loginInit] = fetchMock.mock.calls[0];
    expect(loginUrl).toBe("http://crowdsec.internal:8080/v1/watchers/login");
    expect(JSON.parse(loginInit.body)).toEqual({ machine_id: "ingressi-web", password: "machine-secret", scenarios: [] });
    const [alertsUrl, alertsInit] = fetchMock.mock.calls[1];
    expect(alertsUrl).toContain("/v1/alerts?since=24h");
    expect(alertsUrl).toContain("include_capi=false");
    expect(alertsInit.headers.Authorization).toBe("Bearer jwt-1");
    expect(alertsInit.redirect).toBe("error");
  });

  it("signs in again once when the token is refused", async () => {
    fetchMock
      .mockResolvedValueOnce(reply(200, { token: "old" }))
      .mockResolvedValueOnce(reply(401, { message: "expired" }))
      .mockResolvedValueOnce(reply(200, { token: "new" }))
      .mockResolvedValueOnce(reply(200, []));
    await expect(listAlerts({ since: "1h" })).resolves.toEqual([]);
    expect(fetchMock.mock.calls[3][1].headers.Authorization).toBe("Bearer new");
  });

  it("sends a manual ban as an alert carrying the decision", async () => {
    fetchMock.mockResolvedValueOnce(reply(200, { token: "jwt" })).mockResolvedValueOnce(reply(201, ["42"]));
    await expect(addDecision({ target: "192.0.2.0/24", type: "ban", duration: "4h", reason: "abuse" })).resolves.toBe(42);
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe("http://crowdsec.internal:8080/v1/alerts");
    const [alert] = JSON.parse(init.body);
    expect(alert.scenario).toBe("manual/ingressi");
    expect(alert.source).toEqual({ scope: "Range", value: "192.0.2.0/24", range: "192.0.2.0/24" });
    expect(alert.decisions).toEqual([{ duration: "4h", origin: "cscli", scenario: "abuse", scope: "Range", type: "ban", value: "192.0.2.0/24" }]);
  });

  it("refuses bad decisions before asking CrowdSec", async () => {
    await expect(addDecision({ target: "example.com", type: "ban", duration: "4h", reason: "" })).rejects.toThrow(/IP address/);
    await expect(addDecision({ target: "192.0.2.1", type: "ban", duration: "4 hours", reason: "" })).rejects.toThrow(/Duration/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("names neither the address nor the credentials when CrowdSec is unreachable", async () => {
    fetchMock.mockRejectedValueOnce(Object.assign(new TypeError("fetch failed: crowdsec.internal machine-secret"), { cause: { code: "ECONNREFUSED" } }));
    const error = await listAlerts({ since: "2h" }).catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(CrowdSecUnavailableError);
    expect((error as Error).message).toContain("ECONNREFUSED");
    expect((error as Error).message).not.toContain("crowdsec.internal");
    expect((error as Error).message).not.toContain("machine-secret");
  });

  it("explains refused machine credentials", async () => {
    fetchMock.mockResolvedValueOnce(reply(403, { message: "bad" }));
    await expect(listAlerts({ since: "3h" })).rejects.toThrow(/refused the dashboard's machine credentials/);
  });
});
