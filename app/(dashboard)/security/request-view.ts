/**
 * Presentation of a WAF event's full HTTP request and of the value a rule
 * matched, for the Security events page. Pure, so it renders in tests.
 */
import type { WafMatchedValue, WafRequestView } from "@/src/lib/waf-request-capture";
import { locateMatch } from "@/src/lib/waf-match-locate";
import { visibleText } from "./security-view";

/** Coraza cuts a rule's logdata (its "Matched Data: …" text) to about this many bytes. */
const CORAZA_LOG_DATA_CAP = 280;

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

/** The request as it went over the wire: request line, headers, a blank line, the body kept. */
export function fullRequestText(view: WafRequestView): string {
  const lines = [view.requestLine, ...view.headers.map(([name, value]) => `${name}: ${value}`)];
  return view.body ? `${lines.join("\n")}\n\n${view.body}` : lines.join("\n");
}

/** Text shown line by line: line breaks (CRLF too) kept, other control characters as escapes. */
export function visibleLines(text: string): string {
  return text
    .split("\n")
    .map((line) => visibleText(line.endsWith("\r") ? line.slice(0, -1) : line))
    .join("\n");
}

const BINARY_NOTE =
  "The body is binary: control characters show as escapes such as \\x00, and each byte that is not UTF-8 as \\ufffd (Coraza logs them that way, so their values are lost). Credentials in it cannot be told apart and are not redacted.";

/** What to say about the body under the request; null when it is all there. */
export function bodyNote(view: WafRequestView): string | null {
  const capture = view.capture;
  if (!capture) {
    return !view.body && view.contentLength !== null && view.contentLength > 0
      ? `The client sent a ${formatBytes(view.contentLength)} body that is not stored: the event predates keeping request bodies, keeping them is off in the WAF settings, or the WAF stopped the request before it read the body.`
      : null;
  }
  const notes: string[] = [];
  if (capture.bodyCut) {
    notes.push(`Only the first ${formatBytes(capture.bodyStoredBytes)} of the body is kept${capture.bodyBytes > capture.bodyStoredBytes ? ` (it was ${formatBytes(capture.bodyBytes)})` : ""}.`);
  }
  if (capture.bodyBinary) notes.push(BINARY_NOTE);
  if (notes.length > 0) return notes.join(" ");
  if (capture.bodyBytes === 0 && view.contentLength !== null && view.contentLength > 0) {
    return `The client sent a ${formatBytes(view.contentLength)} body that was not logged: keeping request bodies is off in the WAF settings, or the WAF stopped the request before it read the body.`;
  }
  return null;
}

export type ShownValue = {
  text: string;
  /** The matched text in `text`; -1 when it is not there as logged. */
  start: number;
  end: number;
  /** The value goes on before or after `text`. */
  cutBefore: boolean;
  cutAfter: boolean;
  note: string | null;
};

const TRANSFORMED_NOTE =
  "The rule matched this value after its transformations (decoding, lowercase, whitespace removed…), so the matched text does not appear in it as is.";
const LIBINJECTION_NOTE =
  "libinjection reports the attack's token fingerprint (such as sUEnk for an SQL injection, or \"XSS data\"), not text from the value: the whole value is shown.";
/** The size the stored body shows in place of binary data or a file (waf-request-capture.ts). */
const LEFT_OUT_PLACEHOLDER = /^\[[\d.]+ (?:B|KiB|MiB) of (?:binary|file) data not stored\]$/;
const CUT_NOTE ="Coraza logs only the start of the value (about 280 bytes with the rule's text), and the match lies further in.";

function utf8Length(text: string): number {
  return new TextEncoder().encode(text).length;
}

/**
 * The value to show under "Show the value" for one matched rule: the excerpt
 * kept at ingest around the match when there is one (it holds the match even
 * past the stored body or Coraza's logdata cut), else the value the rule
 * logged, with the match found in it when it is there. Null when there is
 * nothing more to show than the matched text.
 */
export function shownValue(input: {
  ruleId: number;
  variable: string | null;
  found: string | null;
  /** The value from the rule's logdata. */
  logged: string | null;
  matchedData: string | null;
  captured?: readonly WafMatchedValue[] | null;
  /** The rule's message: libinjection rules say so in it. */
  message?: string | null;
}): ShownValue | null {
  const unlocatedNote = (fallback: string) => (input.message && /libinjection/i.test(input.message) ? LIBINJECTION_NOTE : fallback);
  const kept = input.variable ? input.captured?.find((item) => item.ruleId === input.ruleId && item.variable === input.variable) : undefined;
  const loggedSpan = input.logged && input.found ? locateMatch(input.logged, input.found) : null;
  // An excerpt without the match gives way to the logged value when that has
  // it, or when the excerpt is only the size of data the body left out
  // (events stored before such matches were kept).
  const keptUsable =
    kept && (kept.start >= 0 || (!loggedSpan && !(input.logged && LEFT_OUT_PLACEHOLDER.test(kept.value))));
  if (kept && keptUsable && !(kept.value === input.found && kept.offset === 0 && kept.length === kept.value.length)) {
    return {
      text: kept.value,
      start: kept.start,
      end: kept.end,
      cutBefore: kept.offset > 0,
      cutAfter: kept.offset + kept.value.length < kept.length,
      note: kept.start >= 0 ? null : unlocatedNote(TRANSFORMED_NOTE),
    };
  }
  if (!input.logged || input.logged === input.found) return null;
  const span = loggedSpan;
  const capped = input.matchedData !== null && utf8Length(input.matchedData) >= CORAZA_LOG_DATA_CAP - 16;
  return {
    text: input.logged,
    start: span?.start ?? -1,
    end: span?.end ?? -1,
    cutBefore: false,
    cutAfter: capped,
    note: span ? null : capped ? CUT_NOTE : unlocatedNote(TRANSFORMED_NOTE),
  };
}
