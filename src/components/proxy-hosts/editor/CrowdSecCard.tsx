"use client";

import Link from "next/link";
import { ChoiceCards } from "@/components/ui/ChoiceCards";
import type { CrowdSecHostMode } from "@/lib/crowdsec/host-mode";
import { EditorCard, FieldError, WasHint, useEditor } from "./fields";

/** The CrowdSec bouncer on this host: the global setting, on or off. Shown when CrowdSec is configured. */
export function CrowdSecCard() {
  const { form, update, data } = useEditor();
  const global = data.crowdsecGlobal;
  if (!global) return null;
  const inherited = !global.enabled
    ? "Off: CrowdSec is turned off in its settings."
    : global.appliesToAll
      ? "On: the CrowdSec settings apply it to every host."
      : "Off: the CrowdSec settings cover only hosts that turn it on.";
  const modes: { value: CrowdSecHostMode; label: string; description: string; dot: string }[] = [
    { value: "inherit", label: "Global setting", description: inherited, dot: "bg-soft" },
    {
      value: "on",
      label: "On",
      description: global.enabled
        ? "Addresses with a CrowdSec decision are blocked before anything else runs."
        : "Takes effect once CrowdSec is turned on in its settings.",
      dot: "bg-waf",
    },
    { value: "off", label: "Off", description: "CrowdSec decisions are not checked on this host.", dot: "bg-soft" },
  ];
  return (
    <EditorCard
      id="crowdsec"
      title="CrowdSec"
      description="Blocks client addresses that CrowdSec has decisions for (its own detections and the community blocklist), in front of the WAF."
      actions={
        data.canReadCrowdSec ? (
          <span className="flex flex-wrap gap-3 text-[13px]">
            <Link href="/crowdsec/decisions" className="text-brand underline-offset-4 hover:underline">
              Decisions
            </Link>
            <Link href="/crowdsec/settings" className="text-brand underline-offset-4 hover:underline">
              CrowdSec settings
            </Link>
          </span>
        ) : undefined
      }
    >
      <div className="flex flex-col gap-1.5">
        <span id="f-crowdsec-mode-label" className="flex flex-wrap items-center gap-2 text-[13px] font-medium">
          Mode
          <WasHint group="crowdsec" />
        </span>
        <ChoiceCards
          id="f-crowdsec-mode"
          labelledBy="f-crowdsec-mode-label"
          value={form.crowdsec}
          minWidth={180}
          onChange={(mode) => update((f) => ({ ...f, crowdsec: mode }))}
          options={modes}
        />
        <FieldError id="f-crowdsec-mode" />
      </div>
    </EditorCard>
  );
}
