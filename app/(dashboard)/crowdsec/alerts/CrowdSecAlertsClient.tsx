"use client";

import { useState, useTransition, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { AppDialog } from "@/components/ui/AppDialog";
import { Banner } from "@/components/ui/Banner";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/EmptyState";
import { Input } from "@/components/ui/input";
import { Pagination } from "@/components/ui/Pagination";
import { SectionCard } from "@/components/ui/SectionCard";
import { SegmentedControl } from "@/components/ui/SegmentedControl";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { CrowdSecAlert } from "@/src/lib/crowdsec/lapi-client";
import { CROWDSEC_RANGES, type CrowdSecRange } from "@/src/lib/crowdsec/ranges";
import { getCrowdSecAlertAction } from "../actions";
import { CrowdSecError, CrowdSecShell } from "../CrowdSecShell";
import { BanDialog } from "../decisions/BanDialog";
import { formatWhen, sourceOf } from "../format";

const PER_PAGE = 50;

type Filters = { ip: string; scenario: string; origin: string };

export type CrowdSecAlertsProps = {
  configured: boolean;
  range: CrowdSecRange;
  filters: Filters;
  alerts: CrowdSecAlert[];
  limit: number;
  error: string | null;
  canWrite: boolean;
  canOpenSecurity: boolean;
};

export default function CrowdSecAlertsClient({ configured, range, filters, alerts, limit, error, canWrite, canOpenSecurity }: CrowdSecAlertsProps) {
  const router = useRouter();
  const [draft, setDraft] = useState<Filters>(filters);
  const [page, setPage] = useState(1);
  const [detail, setDetail] = useState<CrowdSecAlert | null>(null);
  const [banTarget, setBanTarget] = useState<string | null>(null);
  const [loading, startLoading] = useTransition();

  const go = (next: Filters, nextRange: CrowdSecRange = range) => {
    const params = new URLSearchParams({ range: nextRange });
    for (const [key, value] of Object.entries(next)) if (value.trim()) params.set(key, value.trim());
    setPage(1);
    router.push(`/crowdsec/alerts?${params}`);
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    go(draft);
  };
  const open = (alert: CrowdSecAlert) =>
    startLoading(async () => {
      const result = await getCrowdSecAlertAction(alert.id);
      if (result.ok) setDetail(result.value);
      else toast.error(result.error);
    });

  const shown = alerts.slice((page - 1) * PER_PAGE, page * PER_PAGE);
  return (
    <CrowdSecShell
      title="Alerts"
      description={`What CrowdSec detected in Caddy's access log, ${CROWDSEC_RANGES[range].label}.`}
      configured={configured}
      canOpenSecurity={canOpenSecurity}
      actions={
        <SegmentedControl
          label="Time range"
          mono
          value={range}
          onChange={(next) => go(filters, next)}
          options={(Object.keys(CROWDSEC_RANGES) as CrowdSecRange[]).map((value) => ({ value, label: value }))}
        />
      }
    >
      <form onSubmit={submit} className="flex flex-wrap items-end gap-2" aria-label="Filter alerts">
        <label className="flex flex-col gap-1 text-[13px] font-medium">
          Source address or range
          <Input className="num w-56" value={draft.ip} onChange={(e) => setDraft({ ...draft, ip: e.target.value })} placeholder="203.0.113.7" />
        </label>
        <label className="flex flex-col gap-1 text-[13px] font-medium">
          Scenario
          <Input className="num w-72" value={draft.scenario} onChange={(e) => setDraft({ ...draft, scenario: e.target.value })} placeholder="crowdsecurity/http-probing" />
        </label>
        <label className="flex flex-col gap-1 text-[13px] font-medium">
          Origin
          <Input className="num w-40" value={draft.origin} onChange={(e) => setDraft({ ...draft, origin: e.target.value })} placeholder="crowdsec" />
        </label>
        <Button type="submit">Filter</Button>
        {(filters.ip || filters.scenario || filters.origin) && (
          <Button type="button" variant="outline" onClick={() => { setDraft({ ip: "", scenario: "", origin: "" }); go({ ip: "", scenario: "", origin: "" }); }}>
            Clear
          </Button>
        )}
      </form>
      {error && <CrowdSecError message={error} />}
      {alerts.length >= limit && <Banner tone="info">Showing the newest {limit} alerts; narrow the filters to see older ones.</Banner>}
      <SectionCard title="Alerts" count={alerts.length} headingLevel={2}>
        {alerts.length === 0 ? (
          <EmptyState compact title="No alerts" description="Nothing matches the filters in this period." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>When</TableHead>
                <TableHead>Scenario</TableHead>
                <TableHead>Source</TableHead>
                <TableHead className="text-right">Events</TableHead>
                <TableHead>Decision</TableHead>
                <TableHead className="w-0" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((alert) => {
                const source = sourceOf(alert);
                const decision = alert.decisions?.[0];
                return (
                  <TableRow key={alert.id}>
                    <TableCell className="num whitespace-nowrap">{formatWhen(alert.start_at ?? alert.created_at)}</TableCell>
                    <TableCell className="num [overflow-wrap:anywhere]">
                      {alert.scenario}
                      {alert.simulated && <span className="ml-2 text-xs text-muted-foreground">simulated</span>}
                    </TableCell>
                    <TableCell>
                      <span className="num">{source.address}</span>
                      {source.where && <span className="block text-xs text-muted-foreground">{source.where}</span>}
                    </TableCell>
                    <TableCell className="num text-right">{alert.events_count ?? 0}</TableCell>
                    <TableCell className="num">{decision ? `${decision.type} · ${decision.duration}` : "—"}</TableCell>
                    <TableCell className="whitespace-nowrap text-right">
                      <Button size="sm" variant="ghost" disabled={loading} onClick={() => open(alert)}>
                        Details
                      </Button>
                      {canWrite && source.address !== "unknown" && (
                        <Button size="sm" variant="ghost" onClick={() => setBanTarget(source.address)}>
                          Ban
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
        <Pagination className="px-5 py-3" page={page} perPage={PER_PAGE} total={alerts.length} noun="alerts" onPageChange={setPage} />
      </SectionCard>
      <AlertDetail alert={detail} onClose={() => setDetail(null)} />
      {banTarget && <BanDialog initialTarget={banTarget} onClose={() => setBanTarget(null)} />}
    </CrowdSecShell>
  );
}

function AlertDetail({ alert, onClose }: { alert: CrowdSecAlert | null; onClose: () => void }) {
  if (!alert) return null;
  const source = sourceOf(alert);
  return (
    <AppDialog open onClose={onClose} title={`Alert #${alert.id}`} maxWidth="xl">
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-[13px]">
        <dt className="text-muted-foreground">Scenario</dt>
        <dd className="num [overflow-wrap:anywhere]">{alert.scenario}</dd>
        <dt className="text-muted-foreground">Message</dt>
        <dd className="[overflow-wrap:anywhere]">{alert.message ?? "—"}</dd>
        <dt className="text-muted-foreground">Source</dt>
        <dd>
          <span className="num">{source.address}</span> {source.where && <span className="text-muted-foreground">· {source.where}</span>}
        </dd>
        <dt className="text-muted-foreground">Period</dt>
        <dd className="num">
          {formatWhen(alert.start_at)} → {formatWhen(alert.stop_at)}
        </dd>
        <dt className="text-muted-foreground">Machine</dt>
        <dd className="num">{alert.machine_id ?? "—"}</dd>
      </dl>
      {(alert.decisions?.length ?? 0) > 0 && (
        <section className="mt-4">
          <h3 className="mb-1 text-[13px] font-semibold">Decisions</h3>
          <ul className="num text-[13px]">
            {alert.decisions!.map((decision) => (
              <li key={decision.id}>
                #{decision.id} · {decision.type} {decision.scope}:{decision.value} · {decision.duration} · {decision.origin}
              </li>
            ))}
          </ul>
        </section>
      )}
      {(alert.events?.length ?? 0) > 0 && (
        <section className="mt-4">
          <h3 className="mb-1 text-[13px] font-semibold">Events ({alert.events!.length})</h3>
          <ol className="flex max-h-80 flex-col gap-2 overflow-auto text-xs">
            {alert.events!.slice(0, 50).map((event, index) => (
              <li key={index} className="rounded-md border border-line p-2">
                <div className="num mb-1 text-muted-foreground">{formatWhen(event.timestamp)}</div>
                <dl className="grid grid-cols-[max-content_1fr] gap-x-3">
                  {event.meta.map((item) => (
                    <div key={item.key} className="contents">
                      <dt className="text-muted-foreground">{item.key}</dt>
                      <dd className="num [overflow-wrap:anywhere]">{item.value}</dd>
                    </div>
                  ))}
                </dl>
              </li>
            ))}
          </ol>
        </section>
      )}
    </AppDialog>
  );
}
