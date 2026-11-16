"use client";

import { useState, useTransition } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { Banner } from "@/components/ui/Banner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SectionCard } from "@/components/ui/SectionCard";
import { StatusDot } from "@/components/ui/StatusDot";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { CrowdSecHostUse } from "@/src/lib/crowdsec/dashboard";
import type { CrowdSecSettings } from "@/src/lib/crowdsec/settings";
import type { ManagedStatus } from "@/src/lib/crowdsec/managed-sync";
import { saveCrowdSecSettingsAction } from "../actions";
import { CrowdSecShell } from "../CrowdSecShell";
import { formatWhen } from "../format";

const MODE_LABEL = { inherit: "Global setting", on: "On", off: "Off" } as const;

export type CrowdSecSettingsProps = {
  configured: boolean;
  lapiUrl: string | null;
  settings: CrowdSecSettings;
  hosts: CrowdSecHostUse[];
  accessLog: { enabled: boolean; json: boolean };
  lapi: { ok: true } | { ok: false; error: string } | null;
  snapshot: ManagedStatus["snapshot"];
  canWrite: boolean;
  canOpenSecurity: boolean;
  canEditHosts: boolean;
};

type BouncerRow = { name?: string; last_pull?: string; ip_address?: string; type?: string; version?: string };

function bouncersOf(snapshot: ManagedStatus["snapshot"]): BouncerRow[] {
  return Array.isArray(snapshot?.bouncers) ? (snapshot.bouncers as BouncerRow[]) : [];
}

function collectionsOf(snapshot: ManagedStatus["snapshot"]): { name: string; status?: string; version?: string }[] {
  const hub = snapshot?.hub as { collections?: { name: string; status?: string; local_version?: string; version?: string }[] } | undefined;
  return (hub?.collections ?? []).map((item) => ({ name: item.name, status: item.status, version: item.local_version ?? item.version }));
}

export default function CrowdSecSettingsClient({ configured, lapiUrl, settings, hosts, accessLog, lapi, snapshot, canWrite, canOpenSecurity, canEditHosts }: CrowdSecSettingsProps) {
  const router = useRouter();
  const [form, setForm] = useState<CrowdSecSettings>(settings);
  const [pending, start] = useTransition();
  const dirty = JSON.stringify(form) !== JSON.stringify(settings);
  const save = () =>
    start(async () => {
      const result = await saveCrowdSecSettingsAction(form);
      if (result.ok) {
        toast.success("CrowdSec settings saved and applied");
        router.refresh();
      } else toast.error(result.error);
    });
  const bouncers = bouncersOf(snapshot);
  const collections = collectionsOf(snapshot);
  const enabledHosts = hosts.filter((host) => host.enabled);

  return (
    <CrowdSecShell
      title="CrowdSec settings"
      description="The Caddy bouncer blocks client addresses CrowdSec has decisions for, first on every route of the hosts that use it."
      configured={configured}
      canOpenSecurity={canOpenSecurity}
    >
      {(!accessLog.enabled || !accessLog.json) && (
        <Banner tone="warn" title="CrowdSec cannot read Caddy's access log.">
          {accessLog.enabled ? "The access log is in console format; CrowdSec's Caddy parser needs JSON." : "Access logging is off, so there is nothing to analyse."}{" "}
          Change it under <Link className="underline" href="/settings">Settings → Logging</Link>. The bouncer still blocks community blocklist and manual decisions.
        </Banner>
      )}
      <SectionCard title="Bouncer" headingLevel={2} padded>
        <div className="flex flex-col gap-4 text-[13px]">
          <label className="flex items-start gap-3">
            <Switch checked={form.enabled} disabled={!canWrite} onCheckedChange={(enabled) => setForm({ ...form, enabled })} />
            <span>
              <span className="block font-medium">CrowdSec on</span>
              <span className="text-muted-foreground">Off: no host uses the bouncer, whatever its own setting.</span>
            </span>
          </label>
          <label className="flex items-start gap-3">
            <Switch checked={form.apply_to_all_hosts} disabled={!canWrite} onCheckedChange={(apply_to_all_hosts) => setForm({ ...form, apply_to_all_hosts })} />
            <span>
              <span className="block font-medium">Apply to all hosts</span>
              <span className="text-muted-foreground">Hosts set to &quot;Global setting&quot; use the bouncer. A host set to On or Off in its editor keeps its own choice.</span>
            </span>
          </label>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="flex flex-col gap-1 font-medium">
              Pull interval
              <Input className="num" value={form.ticker_interval} disabled={!canWrite} onChange={(e) => setForm({ ...form, ticker_interval: e.target.value })} />
              <span className="font-normal text-muted-foreground">How often Caddy pulls new decisions (5s to 1h; default 60s).</span>
            </label>
            <label className="flex flex-col gap-1 font-medium">
              LAPI timeout
              <Input className="num" value={form.lapi_timeout} disabled={!canWrite} onChange={(e) => setForm({ ...form, lapi_timeout: e.target.value })} />
              <span className="font-normal text-muted-foreground">Time limit of each request to CrowdSec (1s to 2m; default 10s).</span>
            </label>
          </div>
          {canWrite && (
            <div className="flex gap-2">
              <Button onClick={save} disabled={!dirty || pending}>
                Save and apply
              </Button>
              {dirty && (
                <Button variant="outline" onClick={() => setForm(settings)} disabled={pending}>
                  Discard
                </Button>
              )}
            </div>
          )}
        </div>
      </SectionCard>
      <SectionCard title="Connection" headingLevel={2} padded>
        <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-[13px]">
          <dt className="text-muted-foreground">Local API</dt>
          <dd className="num">{lapiUrl ?? "not configured"}</dd>
          <dt className="text-muted-foreground">Dashboard sign-in</dt>
          <dd>
            {lapi === null ? (
              <StatusDot tone="off" label="Not configured" />
            ) : lapi.ok ? (
              <StatusDot tone="ok" label="Connected" />
            ) : (
              <StatusDot tone="bad" label={lapi.error} />
            )}
          </dd>
          {bouncers.map((bouncer) => (
            <div key={bouncer.name} className="contents">
              <dt className="text-muted-foreground">Bouncer {bouncer.name}</dt>
              <dd className="num">
                {bouncer.last_pull ? `last pull ${formatWhen(bouncer.last_pull)}` : "never pulled"}
                {bouncer.version ? ` · ${bouncer.version}` : ""}
              </dd>
            </div>
          ))}
          {snapshot?.at && (
            <>
              <dt className="text-muted-foreground">Status from CrowdSec</dt>
              <dd className="num">{formatWhen(snapshot.at)}</dd>
            </>
          )}
        </dl>
        {collections.length > 0 && (
          <div className="mt-4">
            <h3 className="mb-1 text-[13px] font-semibold">Installed collections</h3>
            <ul className="num flex flex-wrap gap-2 text-xs">
              {collections.map((item) => (
                <li key={item.name} className="rounded-full border border-line2 px-2 py-0.5">
                  {item.name}
                  {item.version ? ` ${item.version}` : ""}
                </li>
              ))}
            </ul>
          </div>
        )}
      </SectionCard>
      <SectionCard title="Hosts" count={`${enabledHosts.filter((host) => host.protected).length} / ${enabledHosts.length}`} description="Whether each enabled host uses the bouncer now." headingLevel={2}>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Host</TableHead>
              <TableHead>Host setting</TableHead>
              <TableHead>Bouncer</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {enabledHosts.map((host) => (
              <TableRow key={host.id}>
                <TableCell>
                  {canEditHosts ? (
                    <Link href={`/proxy-hosts/${host.id}`} className="underline-offset-4 hover:underline">
                      {host.name}
                    </Link>
                  ) : (
                    host.name
                  )}
                </TableCell>
                <TableCell>{MODE_LABEL[host.mode]}</TableCell>
                <TableCell>{host.protected ? <StatusDot tone="ok" label="On" /> : <StatusDot tone="off" label="Off" />}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </SectionCard>
    </CrowdSecShell>
  );
}
