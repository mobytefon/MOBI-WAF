"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import type { WafRequestView } from "@/src/lib/waf-request-capture";
import { wafRequestAction } from "./request-actions";
import { bodyNote, fullRequestText, visibleLines, type ShownValue } from "./request-view";
import { visibleText } from "./security-view";

export type WafRequestState = { status: "loading" } | { status: "error"; error: string } | { status: "ready"; view: WafRequestView };

const PRE_CLASS =
  "num m-0 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-background px-3 py-2.5 text-xs leading-[18px]";

/** Loads a WAF event's full request once the event is opened. */
export function useWafRequest(eventId: string | null): WafRequestState {
  const [state, setState] = useState<WafRequestState>({ status: "loading" });
  useEffect(() => {
    if (!eventId) {
      setState({ status: "error", error: "This event has no transaction id, so its request cannot be read." });
      return;
    }
    let cancelled = false;
    setState({ status: "loading" });
    wafRequestAction(eventId).then(
      (result) => {
        if (!cancelled) setState(result.ok ? { status: "ready", view: result.value } : { status: "error", error: result.error });
      },
      () => {
        if (!cancelled) setState({ status: "error", error: "Could not read this event's request." });
      }
    );
    return () => {
      cancelled = true;
    };
  }, [eventId]);
  return state;
}

/** A matched value with the match marked, and what is left out of it. */
export function MatchedValue({ shown }: { shown: ShownValue }) {
  const { text, start, end } = shown;
  const marked = start >= 0 && end > start && end <= text.length;
  return (
    <div className="flex flex-col gap-1">
      <pre className={cn(PRE_CLASS, "max-h-40")}>
        {shown.cutBefore && <span className="text-muted-foreground">… </span>}
        {marked ? (
          <>
            {visibleText(text.slice(0, start))}
            <mark className="rounded-sm bg-waf/25 px-0.5 text-foreground">{visibleText(text.slice(start, end))}</mark>
            {visibleText(text.slice(end))}
          </>
        ) : (
          visibleText(text)
        )}
        {shown.cutAfter && <span className="text-muted-foreground"> …</span>}
      </pre>
      {shown.note && <span className="text-xs text-muted-foreground">{shown.note}</span>}
    </div>
  );
}

/** The request line, every header and the body kept, as the WAF saw them. */
export function FullHttpRequest({ state }: { state: WafRequestState }) {
  const view = state.status === "ready" ? state.view : null;
  const text = view ? fullRequestText(view) : "";
  const note = view ? bodyNote(view) : null;

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Copied the request.");
    } catch {
      toast.error("The clipboard is not available here; select the text and copy it.");
    }
  }

  return (
    <section aria-label="Full HTTP request" className="flex flex-col gap-1.5">
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="m-0 text-[13px] font-semibold text-muted-foreground">Full HTTP request</h3>
        {view && (
          <button type="button" className="text-[13px] text-brand underline-offset-4 hover:text-foreground hover:underline" onClick={copy}>
            Copy
          </button>
        )}
      </div>
      {state.status === "loading" && (
        <p role="status" className="m-0 text-[13px] text-muted-foreground">
          Reading the request…
        </p>
      )}
      {state.status === "error" && <p className="m-0 text-[13px] text-muted-foreground">{state.error}</p>}
      {view && (
        <>
          <pre className={cn(PRE_CLASS, "max-h-80")}>{visibleLines(text)}</pre>
          {note && <span className="text-xs text-muted-foreground">{note}</span>}
        </>
      )}
    </section>
  );
}
