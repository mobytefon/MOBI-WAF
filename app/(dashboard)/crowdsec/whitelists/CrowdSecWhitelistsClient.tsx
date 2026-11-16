"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { AppDialog } from "@/components/ui/AppDialog";
import { Banner } from "@/components/ui/Banner";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/EmptyState";
import { Input } from "@/components/ui/input";
import { SectionCard } from "@/components/ui/SectionCard";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { CrowdSecWhitelist, CrowdSecWhitelistInput, WhitelistKind } from "@/src/lib/models/crowdsec-whitelists";
import type { ManagedApplyResult } from "@/src/lib/crowdsec/managed-sync";
import {
  createCrowdSecWhitelistAction,
  deleteCrowdSecWhitelistAction,
  reapplyCrowdSecWhitelistsAction,
  updateCrowdSecWhitelistAction,
} from "../actions";
import { CrowdSecShell } from "../CrowdSecShell";
import { formatWhen } from "../format";

const KINDS: { value: WhitelistKind; label: string; placeholder: string; hint: string }[] = [
  { value: "ip", label: "IP addresses", placeholder: "192.0.2.10\n2001:db8::1", hint: "One address per line (or separated by commas)." },
  { value: "cidr", label: "CIDR ranges", placeholder: "10.0.0.0/8\n192.168.0.0/16", hint: "One range per line." },
  { value: "asn", label: "AS numbers", placeholder: "131429, 45899, 18403", hint: "Networks by AS number (AS prefix optional); matched with the GeoIP ASN database." },
  { value: "country", label: "Countries", placeholder: "VN", hint: "Two-letter country codes (ISO 3166-1)." },
  { value: "expression", label: "Expression", placeholder: "evt.Meta.http_path startsWith '/healthz'", hint: "One CrowdSec (expr) expression on the event; it whitelists when true." },
];
const KIND_LABEL = Object.fromEntries(KINDS.map((kind) => [kind.value, kind.label])) as Record<WhitelistKind, string>;

type Row = CrowdSecWhitelist & { yaml: string };
type Draft = { id: number | null; name: string; kind: WhitelistKind; values: string; reason: string; enabled: boolean };

export type CrowdSecWhitelistsProps = {
  configured: boolean;
  generation: number;
  whitelists: Row[];
  /** null when the shared directory with the crowdsec container is missing. */
  managed: { written: number | null; result: ManagedApplyResult | null } | null;
  canWrite: boolean;
  canOpenSecurity: boolean;
};

function ApplyStatus({ generation, managed }: Pick<CrowdSecWhitelistsProps, "generation" | "managed">) {
  if (!managed) {
    return (
      <Banner tone="warn" title="The whitelists are not handed to CrowdSec.">
        CROWDSEC_MANAGED_DIR is not set or its directory is missing on this web node; start the stack with docker-compose.crowdsec.yml.
      </Banner>
    );
  }
  const result = managed.result;
  if (result && result.generation === generation) {
    return result.ok ? (
      <Banner tone="ok">Applied by CrowdSec {formatWhen(result.at)}.</Banner>
    ) : (
      <Banner tone="bad" title="CrowdSec refused the whitelists, so it keeps the previous ones.">
        <span className="num [overflow-wrap:anywhere]">{result.message}</span>
      </Banner>
    );
  }
  return <Banner tone="info">Waiting for CrowdSec to apply the latest change (this takes a few seconds).</Banner>;
}

export default function CrowdSecWhitelistsClient({ configured, generation, whitelists, managed, canWrite, canOpenSecurity }: CrowdSecWhitelistsProps) {
  const router = useRouter();
  const [draft, setDraft] = useState<Draft | null>(null);
  const [preview, setPreview] = useState<Row | null>(null);
  const [pending, start] = useTransition();

  const edit = (row: Row | null) =>
    setDraft(
      row
        ? { id: row.id, name: row.name, kind: row.kind, values: row.kind === "expression" ? row.values[0] ?? "" : row.values.join("\n"), reason: row.reason, enabled: row.enabled }
        : { id: null, name: "", kind: "ip", values: "", reason: "", enabled: true }
    );
  const inputOf = (value: Draft): CrowdSecWhitelistInput => ({ name: value.name, kind: value.kind, values: value.values, reason: value.reason, enabled: value.enabled });
  const save = () => {
    if (!draft) return;
    start(async () => {
      const result = draft.id === null ? await createCrowdSecWhitelistAction(inputOf(draft)) : await updateCrowdSecWhitelistAction(draft.id, inputOf(draft));
      if (result.ok) {
        toast.success(`Saved "${result.value.name}"; CrowdSec applies it in a few seconds`);
        setDraft(null);
        router.refresh();
      } else toast.error(result.error);
    });
  };
  const toggle = (row: Row) =>
    start(async () => {
      const result = await updateCrowdSecWhitelistAction(row.id, { name: row.name, kind: row.kind, values: row.values, reason: row.reason, enabled: !row.enabled });
      if (result.ok) router.refresh();
      else toast.error(result.error);
    });
  const remove = (row: Row) =>
    start(async () => {
      const result = await deleteCrowdSecWhitelistAction(row.id);
      if (result.ok) {
        toast.success(`Deleted "${row.name}"`);
        router.refresh();
      } else toast.error(result.error);
    });
  const reapply = () =>
    start(async () => {
      const result = await reapplyCrowdSecWhitelistsAction();
      if (result.ok) {
        toast.success("Handed to CrowdSec again");
        router.refresh();
      } else toast.error(result.error);
    });

  const kind = KINDS.find((entry) => entry.value === draft?.kind) ?? KINDS[0];
  return (
    <CrowdSecShell
      title="Whitelists"
      description="Log lines that match a whitelist raise no CrowdSec alert, so no ban. IP and CIDR entries are also kept out of the community blocklist."
      configured={configured}
      canOpenSecurity={canOpenSecurity}
      actions={
        canWrite ? (
          <span className="flex gap-2">
            <Button variant="outline" disabled={pending} onClick={reapply}>
              Apply again
            </Button>
            <Button onClick={() => edit(null)}>Add whitelist</Button>
          </span>
        ) : undefined
      }
    >
      <ApplyStatus generation={generation} managed={managed} />
      <SectionCard title="Whitelists" count={whitelists.length} headingLevel={2}>
        {whitelists.length === 0 ? (
          <EmptyState compact title="No whitelists" description="Add your monitoring, partners' networks or trusted ASNs so CrowdSec never bans them." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Values</TableHead>
                <TableHead>On</TableHead>
                <TableHead className="w-0" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {whitelists.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>
                    {row.name}
                    {row.reason && <span className="block text-xs text-muted-foreground">{row.reason}</span>}
                  </TableCell>
                  <TableCell>{KIND_LABEL[row.kind]}</TableCell>
                  <TableCell className="num max-w-md [overflow-wrap:anywhere]">
                    {row.values.slice(0, 8).join(", ")}
                    {row.values.length > 8 && ` +${row.values.length - 8} more`}
                  </TableCell>
                  <TableCell>
                    <Switch checked={row.enabled} disabled={!canWrite || pending} onCheckedChange={() => toggle(row)} aria-label={`Whitelist ${row.name} on`} />
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-right">
                    <Button size="sm" variant="ghost" onClick={() => setPreview(row)}>
                      YAML
                    </Button>
                    {canWrite && (
                      <>
                        <Button size="sm" variant="ghost" onClick={() => edit(row)}>
                          Edit
                        </Button>
                        <Button size="sm" variant="ghost" disabled={pending} onClick={() => remove(row)}>
                          Delete
                        </Button>
                      </>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </SectionCard>
      {draft && (
        <AppDialog
          open
          onClose={() => setDraft(null)}
          title={draft.id === null ? "Add a whitelist" : `Edit "${draft.name}"`}
          maxWidth="lg"
          submitLabel="Save"
          onSubmit={save}
          isSubmitting={pending}
        >
          <div className="flex flex-col gap-3 text-[13px]">
            <label className="flex flex-col gap-1 font-medium">
              Name
              <Input autoFocus value={draft.name} maxLength={100} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="Trusted ASNs" />
            </label>
            <label className="flex flex-col gap-1 font-medium">
              Kind
              <select
                className="h-9 rounded-md border border-line2 bg-panel px-2"
                value={draft.kind}
                onChange={(e) => setDraft({ ...draft, kind: e.target.value as WhitelistKind })}
              >
                {KINDS.map((entry) => (
                  <option key={entry.value} value={entry.value}>
                    {entry.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 font-medium">
              {draft.kind === "expression" ? "Expression" : "Values"}
              <Textarea className="num min-h-28" value={draft.values} onChange={(e) => setDraft({ ...draft, values: e.target.value })} placeholder={kind.placeholder} />
              <span className="font-normal text-muted-foreground">{kind.hint}</span>
            </label>
            <label className="flex flex-col gap-1 font-medium">
              Reason
              <Input value={draft.reason} maxLength={300} onChange={(e) => setDraft({ ...draft, reason: e.target.value })} placeholder="Trusted ASN" />
            </label>
            <label className="flex items-center gap-2 font-medium">
              <Switch checked={draft.enabled} onCheckedChange={(enabled) => setDraft({ ...draft, enabled })} />
              On
            </label>
          </div>
        </AppDialog>
      )}
      {preview && (
        <AppDialog open onClose={() => setPreview(null)} title={`zz-ingressi-${preview.id}.yaml`} maxWidth="lg">
          <p className="mb-2 text-[13px] text-muted-foreground">The parser whitelist CrowdSec loads in /etc/crowdsec/parsers/s02-enrich/.</p>
          <pre className="num max-h-96 overflow-auto rounded-md border border-line bg-raise p-3 text-xs">{preview.yaml}</pre>
        </AppDialog>
      )}
    </CrowdSecShell>
  );
}
