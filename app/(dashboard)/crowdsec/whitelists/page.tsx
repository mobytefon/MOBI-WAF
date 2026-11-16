import { requirePermission } from "@/src/lib/auth";
import { can } from "@/src/lib/permissions";
import { isCrowdSecConfigured } from "@/src/lib/crowdsec/config";
import { readManagedStatus } from "@/src/lib/crowdsec/managed-sync";
import { renderWhitelistYaml } from "@/src/lib/crowdsec/whitelist-render";
import { readCrowdSecWhitelistState } from "@/src/lib/models/crowdsec-whitelists";
import CrowdSecWhitelistsClient from "./CrowdSecWhitelistsClient";

export const dynamic = "force-dynamic";
export const metadata = { title: "CrowdSec whitelists" };

/** Whitelists CrowdSec applies to Caddy's log lines (no alert, no ban), and how far CrowdSec has applied them. */
export default async function CrowdSecWhitelistsPage() {
  const { access } = await requirePermission("crowdsec:read");
  const [state, managed] = await Promise.all([readCrowdSecWhitelistState(), readManagedStatus()]);
  return (
    <CrowdSecWhitelistsClient
      configured={isCrowdSecConfigured()}
      generation={state.generation}
      whitelists={state.entries.map((entry) => ({ ...entry, yaml: renderWhitelistYaml(entry) }))}
      managed={managed.available ? { written: managed.written, result: managed.result } : null}
      canWrite={can(access, "crowdsec:write")}
      canOpenSecurity={can(access, "waf:read")}
    />
  );
}
