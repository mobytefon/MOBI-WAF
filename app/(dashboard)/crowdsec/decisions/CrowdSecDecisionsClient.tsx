"use client";

import { useMemo, useState, useTransition, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/EmptyState";
import { Input } from "@/components/ui/input";
import { Pagination } from "@/components/ui/Pagination";
import { SectionCard } from "@/components/ui/SectionCard";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatCount } from "@/components/ui/chart-format";
import type { ActiveDecision } from "@/src/lib/crowdsec/decisions";
import type { CrowdSecDecision } from "@/src/lib/crowdsec/lapi-client";
import { deleteCrowdSecDecisionAction, lookupCrowdSecAddressAction, unbanCrowdSecAddressAction } from "../actions";
import { CrowdSecError, CrowdSecShell } from "../CrowdSecShell";
import { formatWhen } from "../format";
import { BanDialog } from "./BanDialog";

const PER_PAGE = 50;

export type CrowdSecDecisionsProps = {
  configured: boolean;
  origin: string;
  decisions: ActiveDecision[];
  byOrigin: Record<string, number> | null;
  error: string | null;
  canWrite: boolean;
  canOpenSecurity: boolean;
};

export default function CrowdSecDecisionsClient({ configured, origin, decisions, byOrigin, error, canWrite, canOpenSecurity }: CrowdSecDecisionsProps) {
  const router = useRouter();
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [banning, setBanning] = useState(false);
  const [lookup, setLookup] = useState("");
  const [lookupResult, setLookupResult] = useState<{ address: string; decisions: CrowdSecDecision[] } | null>(null);
  const [pending, start] = useTransition();

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return needle
      ? decisions.filter((decision) => [decision.value, decision.scenario, decision.reason ?? "", decision.origin].some((text) => text.toLowerCase().includes(needle)))
      : decisions;
  }, [decisions, search]);
  const shown = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE);

  const remove = (decision: ActiveDecision) =>
    start(async () => {
      const result = await deleteCrowdSecDecisionAction(decision.id);
      if (result.ok) {
        toast.success(`Deleted the decision for ${decision.value}`);
        router.refresh();
      } else toast.error(result.error);
    });
  const unbanAll = (address: string) =>
    start(async () => {
      const result = await unbanCrowdSecAddressAction(address);
      if (result.ok) {
        toast.success(`Deleted ${result.value} decision(s) for ${address}`);
        setLookupResult(null);
        router.refresh();
      } else toast.error(result.error);
    });
  const runLookup = (event: FormEvent) => {
    event.preventDefault();
    const address = lookup.trim();
    if (!address) return;
    start(async () => {
      const result = await lookupCrowdSecAddressAction(address);
      if (result.ok) setLookupResult({ address, decisions: result.value });
      else toast.error(result.error);
    });
  };

  const origins = byOrigin ? Object.entries(byOrigin).sort((a, b) => b[1] - a[1]) : [];
  return (
    <CrowdSecShell
      title="Decisions"
      description="Addresses the Caddy bouncer blocks. CrowdSec adds them from its scenarios; you can add and delete them here."
      configured={configured}
      canOpenSecurity={canOpenSecurity}
      actions={canWrite && configured ? <Button onClick={() => setBanning(true)}>Ban an address</Button> : undefined}
    >
      {error && <CrowdSecError message={error} />}
      {origins.length > 0 && (
        <div className="flex flex-wrap gap-2 text-[13px]" aria-label="Active decisions by origin">
          <Link href="/crowdsec/decisions" className={`rounded-full border px-3 py-1 ${origin ? "border-line2" : "border-brand bg-brand-tint"}`}>
            All local
          </Link>
          {origins.map(([name, count]) => {
            const label = (
              <>
                <span className="num">{name}</span> · {formatCount(count)}
              </>
            );
            // The community blocklist and other lists are too large to list: look an address up below.
            return name === "CAPI" || name.startsWith("lists") ? (
              <span key={name} className="rounded-full border border-line2 px-3 py-1" title="Look an address up below">
                {label}
              </span>
            ) : (
              <Link
                key={name}
                href={`/crowdsec/decisions?origin=${encodeURIComponent(name)}`}
                className={`rounded-full border px-3 py-1 ${origin === name ? "border-brand bg-brand-tint" : "border-line2"}`}
              >
                {label}
              </Link>
            );
          })}
        </div>
      )}
      <SectionCard title="Look up an address" description="Every active decision for it, community blocklist included." headingLevel={2} padded>
        <form onSubmit={runLookup} className="flex flex-wrap gap-2">
          <Input className="num w-64" value={lookup} onChange={(e) => setLookup(e.target.value)} placeholder="203.0.113.7" aria-label="Address or range" />
          <Button type="submit" variant="outline" disabled={pending || !configured}>
            Look up
          </Button>
        </form>
        {lookupResult && (
          <div className="mt-3 text-[13px]">
            {lookupResult.decisions.length === 0 ? (
              <p>No active decision for <span className="num">{lookupResult.address}</span>: the bouncer lets it through.</p>
            ) : (
              <>
                <ul className="num flex flex-col gap-1">
                  {lookupResult.decisions.map((decision) => (
                    <li key={decision.id}>
                      {decision.type} {decision.scope}:{decision.value} · {decision.origin} · {decision.scenario} · {decision.duration}
                    </li>
                  ))}
                </ul>
                {canWrite && (
                  <Button className="mt-2" size="sm" variant="outline" disabled={pending} onClick={() => unbanAll(lookupResult.address)}>
                    Delete every decision for {lookupResult.address}
                  </Button>
                )}
              </>
            )}
          </div>
        )}
      </SectionCard>
      <SectionCard
        title="Active decisions"
        count={filtered.length}
        headingLevel={2}
        actions={<Input className="w-56" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} placeholder="Search" aria-label="Search decisions" />}
      >
        {filtered.length === 0 ? (
          <EmptyState compact title="No active decisions" description={search ? "Nothing matches the search." : "CrowdSec has not decided to block anything."} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Target</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Scenario</TableHead>
                <TableHead>Origin</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead className="w-0" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((decision) => (
                <TableRow key={decision.id}>
                  <TableCell>
                    <span className="num">{decision.value}</span>
                    {(decision.country || decision.asName) && (
                      <span className="block text-xs text-muted-foreground">{[decision.country, decision.asName].filter(Boolean).join(" · ")}</span>
                    )}
                  </TableCell>
                  <TableCell className="num">
                    {decision.type}
                    {decision.simulated && <span className="ml-1 text-xs text-muted-foreground">(simulated)</span>}
                  </TableCell>
                  <TableCell className="num [overflow-wrap:anywhere]">{decision.scenario}</TableCell>
                  <TableCell className="num">{decision.origin}</TableCell>
                  <TableCell className="num whitespace-nowrap">{decision.until ? formatWhen(decision.until) : decision.duration}</TableCell>
                  <TableCell className="text-right">
                    {canWrite && (
                      <Button size="sm" variant="ghost" disabled={pending} onClick={() => remove(decision)}>
                        Unban
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <Pagination className="px-5 py-3" page={page} perPage={PER_PAGE} total={filtered.length} noun="decisions" onPageChange={setPage} />
      </SectionCard>
      {banning && <BanDialog onClose={() => setBanning(false)} />}
    </CrowdSecShell>
  );
}
