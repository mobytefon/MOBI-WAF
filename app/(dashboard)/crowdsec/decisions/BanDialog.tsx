"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { AppDialog } from "@/components/ui/AppDialog";
import { Banner } from "@/components/ui/Banner";
import { Input } from "@/components/ui/input";
import { banCrowdSecAction, type BanInput } from "../actions";

const DURATIONS = ["1h", "4h", "24h", "168h", "720h"] as const;

/** Adds a CrowdSec decision for an address or range. A whitelisted address needs a second confirmation. */
export function BanDialog({ initialTarget = "", onClose }: { initialTarget?: string; onClose: () => void }) {
  const router = useRouter();
  const [input, setInput] = useState<BanInput>({ target: initialTarget, type: "ban", duration: "4h", reason: "" });
  const [whitelisted, setWhitelisted] = useState<string | null>(null);
  const [pending, start] = useTransition();

  const submit = () =>
    start(async () => {
      const result = await banCrowdSecAction({ ...input, bypassWhitelist: whitelisted !== null });
      if (result.ok) {
        toast.success(`${input.type === "ban" ? "Banned" : "Decision added for"} ${input.target.trim()} for ${input.duration}`);
        router.refresh();
        onClose();
        return;
      }
      if (result.error.includes("is whitelisted")) setWhitelisted(result.error);
      else toast.error(result.error);
    });

  return (
    <AppDialog
      open
      onClose={onClose}
      title="Add a CrowdSec decision"
      maxWidth="md"
      submitLabel={whitelisted ? "Ban anyway" : "Add decision"}
      onSubmit={submit}
      isSubmitting={pending}
    >
      <div className="flex flex-col gap-3 text-[13px]">
        <label className="flex flex-col gap-1 font-medium">
          IP address or CIDR range
          <Input
            className="num"
            autoFocus
            value={input.target}
            onChange={(e) => {
              setWhitelisted(null);
              setInput({ ...input, target: e.target.value });
            }}
            placeholder="203.0.113.7 or 203.0.113.0/24"
          />
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label className="flex flex-col gap-1 font-medium">
            Type
            <select
              className="h-9 rounded-md border border-line2 bg-panel px-2"
              value={input.type}
              onChange={(e) => setInput({ ...input, type: e.target.value as BanInput["type"] })}
            >
              <option value="ban">Ban (403)</option>
              <option value="throttle">Throttle (429)</option>
              <option value="captcha">Captcha (served as 403)</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 font-medium">
            Duration
            <Input className="num" list="crowdsec-durations" value={input.duration} onChange={(e) => setInput({ ...input, duration: e.target.value })} />
            <datalist id="crowdsec-durations">
              {DURATIONS.map((value) => (
                <option key={value} value={value} />
              ))}
            </datalist>
          </label>
        </div>
        <label className="flex flex-col gap-1 font-medium">
          Reason
          <Input value={input.reason} maxLength={500} onChange={(e) => setInput({ ...input, reason: e.target.value })} placeholder="Manual ban from the dashboard" />
        </label>
        <p className="text-muted-foreground">Caddy picks the decision up at the bouncer&apos;s next pull (the ticker interval in the CrowdSec settings).</p>
        {whitelisted && <Banner tone="warn">{whitelisted}.</Banner>}
      </div>
    </AppDialog>
  );
}
