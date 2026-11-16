import { requirePermission } from "@/src/lib/auth";
import { can } from "@/src/lib/permissions";
import { getLoggingSettings } from "@/src/lib/settings";
import { getCrowdSecEnvironment } from "@/src/lib/crowdsec/config";
import { getCrowdSecSettings } from "@/src/lib/crowdsec/settings";
import { listCrowdSecHostUse } from "@/src/lib/crowdsec/dashboard";
import { checkLapi } from "@/src/lib/crowdsec/lapi-client";
import { readManagedStatus } from "@/src/lib/crowdsec/managed-sync";
import CrowdSecSettingsClient from "./CrowdSecSettingsClient";

export const dynamic = "force-dynamic";
export const metadata = { title: "CrowdSec settings" };

/** Whether and where the bouncer blocks, and the state of the CrowdSec integration. */
export default async function CrowdSecSettingsPage() {
  const { access } = await requirePermission("crowdsec:read");
  const environment = getCrowdSecEnvironment();
  const [settings, hosts, logging, lapi, managed] = await Promise.all([
    getCrowdSecSettings(),
    listCrowdSecHostUse(),
    getLoggingSettings(),
    environment ? checkLapi() : Promise.resolve(null),
    readManagedStatus(),
  ]);
  return (
    <CrowdSecSettingsClient
      configured={environment !== null}
      lapiUrl={environment?.lapiUrl ?? null}
      settings={settings}
      hosts={hosts}
      accessLog={{ enabled: logging?.enabled ?? false, json: (logging?.format ?? "json") === "json" }}
      lapi={lapi}
      snapshot={managed.snapshot}
      canWrite={can(access, "crowdsec:write")}
      canOpenSecurity={can(access, "waf:read")}
      canEditHosts={can(access, "proxy_hosts:write")}
    />
  );
}
