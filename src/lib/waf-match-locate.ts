/**
 * Where a WAF rule's matched text (its TX.0, as the rule's logdata echoes it)
 * lies in the value of the variable it matched. The rule matched the value
 * after its transformations (t:lowercase, t:compressWhitespace,
 * t:removeWhitespace…), so when the text is not in the value as it is, it is
 * looked for again with case and whitespace folded the same ways.
 *
 * Pure and dependency-free: the log parser runs it at ingest and the
 * Security events page in the browser.
 */

export type MatchSpan = { start: number; end: number };

type Folding = "case" | "space" | "nospace";

/** `text` folded, with the position in `text` of each folded character (plus its length at the end). */
function fold(text: string, folding: Folding): { chars: string; index: number[] } {
  let chars = "";
  const index: number[] = [];
  let lastSpace = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (folding !== "case" && /\s/.test(char)) {
      if (folding === "space" && !lastSpace) {
        chars += " ";
        index.push(i);
      }
      lastSpace = true;
      continue;
    }
    lastSpace = false;
    const lower = char.toLowerCase();
    // One folded character per character keeps the index exact.
    chars += lower.length === 1 ? lower : char;
    index.push(i);
  }
  index.push(text.length);
  return { chars, index };
}

function searchFolded(value: string, found: string, folding: Folding): MatchSpan | null {
  const needle = fold(found, folding).chars;
  if (!needle.trim()) return null;
  const haystack = fold(value, folding);
  const at = haystack.chars.indexOf(needle);
  if (at === -1) return null;
  return { start: haystack.index[at], end: haystack.index[at + needle.length - 1] + 1 };
}

/** The span of `found` in `value`, as it is or folded; null when it is not there. */
export function locateMatch(value: string, found: string): MatchSpan | null {
  if (!found || !value) return null;
  const exact = value.indexOf(found);
  if (exact !== -1) return { start: exact, end: exact + found.length };
  for (const folding of ["case", "space", "nospace"] as const) {
    const span = searchFolded(value, found, folding);
    if (span) return span;
  }
  return null;
}

/**
 * A Coraza "Matched Data: <found> found within <VARIABLE>: <value>" logdata,
 * split; null for anything else.
 */
export function splitMatchedLogData(data: string): { found: string; variable: string; value: string } | null {
  const body = data.replace(/^\s*Matched Data: ?/, "");
  const match = body.match(/^([\s\S]*?) found within ([A-Z_]+(?::[^\s:]*)?): ([\s\S]*)$/);
  return match ? { found: match[1], variable: match[2], value: match[3] } : null;
}
