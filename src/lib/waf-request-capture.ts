/**
 * The full request of a WAF event: what the log parser keeps of the request
 * body Coraza logs (audit log part C, waf.log_request_body), and the view of
 * it the Security events page shows as "Full HTTP request".
 *
 * At ingest (captureAuditRequest, called by waf-log-parser's
 * redactAuditEntry on the copy it stores):
 *  - the body is cleaned: credential-named form, multipart and JSON fields
 *    are redacted, file uploads and binary data are replaced by their size;
 *  - it is cut to MAX_STORED_BODY_BYTES;
 *  - for each rule that matched, the value of the variable it matched is
 *    looked up in the whole request (before the cut) and an excerpt around
 *    the matched text is kept, so the page shows where the rule matched even
 *    past the stored body or the ~280 bytes Coraza logs of a value.
 * What is kept goes under the record's own WAF_CAPTURE_KEY.
 *
 * The record is request data: it is read defensively and only ever shown
 * as text.
 */
import { explainWafAuditRecord } from "./waf-explain";
import { locateMatch, splitMatchedLogData, type MatchSpan } from "./waf-match-locate";

/** The audit record key holding what captureAuditRequest kept. */
export const WAF_CAPTURE_KEY = "ingressi_capture";
/** The most of a request body a WAF event keeps. */
export const MAX_STORED_BODY_BYTES = 32 * 1024;
/** The longest excerpt of a matched value kept, and how much of it comes before the match. */
const MAX_VALUE_CHARS = 4096;
const CONTEXT_BEFORE = 1024;
const MAX_MATCHED_VALUES = 20;
/** Bodies parsed as JSON at most this large; larger ones are redacted by pattern. */
const MAX_PARSED_BODY_BYTES = 4 * 1024 * 1024;
const REDACTED = "[redacted]";

export type WafMatchedValue = {
  ruleId: number;
  /** As the rule logged it, e.g. ARGS:json.Body.Items.0.Body.Value. */
  variable: string;
  /** The value, or an excerpt of it around the match. */
  value: string;
  /** Where the excerpt starts in the whole value, and how long the whole value is (characters). */
  offset: number;
  length: number;
  /** The matched text in `value`; -1 when it was not found as logged (transformations). */
  start: number;
  end: number;
};

export type WafRequestCapture = {
  /** Size of the body Coraza logged, and of the part stored. */
  bodyBytes: number;
  bodyStoredBytes: number;
  /** The cleaned body was longer than MAX_STORED_BODY_BYTES and was cut. */
  bodyCut: boolean;
  matchedValues: WafMatchedValue[];
};

export type CredentialTest = (name: string) => boolean;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function utf8Length(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

/**
 * Size of the bytes the client sent as `text`: Coraza's JSON audit log turns
 * each byte that is not UTF-8 into U+FFFD (3 bytes in UTF-8), which would
 * nearly double the size of a binary upload.
 */
function sentBytes(text: string): number {
  let replaced = 0;
  for (let at = text.indexOf("\ufffd"); at !== -1; at = text.indexOf("\ufffd", at + 1)) replaced++;
  return utf8Length(text) - 2 * replaced;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

/** The first `max` bytes of `text`, never ending inside a character. */
function truncateUtf8(text: string, max: number): string {
  if (utf8Length(text) <= max) return text;
  const cut = Buffer.from(text, "utf8").subarray(0, max).toString("utf8");
  return cut.endsWith("\ufffd") ? cut.slice(0, -1) : cut;
}

/** NUL bytes, or many control characters or U+FFFD (bytes that were not UTF-8) in the first 4 KiB. */
function looksBinary(text: string): boolean {
  const sample = text.slice(0, 4096);
  if (sample.includes("\u0000")) return true;
  let odd = 0;
  for (const char of sample) {
    const code = char.codePointAt(0)!;
    if ((code < 0x20 && char !== "\n" && char !== "\r" && char !== "\t") || code === 0xfffd) odd++;
  }
  return sample.length > 0 && odd / sample.length > 0.05;
}

function headerLookup(headers: unknown): (name: string) => string | null {
  return (name) => {
    if (!isRecord(headers)) return null;
    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() !== name) continue;
      const list = (Array.isArray(value) ? value : [value]).filter((item): item is string => typeof item === "string");
      return list.length > 0 ? list.join(", ") : null;
    }
    return null;
  };
}

function decodeFormComponent(text: string): string {
  try {
    return decodeURIComponent(text.replace(/\+/g, " "));
  } catch {
    return text;
  }
}

function formPairs(text: string): Array<[string, string]> {
  return text
    .split("&")
    .filter(Boolean)
    .map((pair) => {
      const at = pair.indexOf("=");
      return at === -1 ? [decodeFormComponent(pair), ""] : [decodeFormComponent(pair.slice(0, at)), decodeFormComponent(pair.slice(at + 1))];
    });
}

function redactFormBody(body: string, isCredential: CredentialTest): string {
  return body
    .split("&")
    .map((pair) => {
      const at = pair.indexOf("=");
      if (at === -1) return pair;
      return isCredential(decodeFormComponent(pair.slice(0, at))) ? `${pair.slice(0, at)}=${REDACTED}` : pair;
    })
    .join("&");
}

/** JSON with the value of every credential-named key replaced. */
function redactJsonBody(body: string, isCredential: CredentialTest): string {
  if (utf8Length(body) <= MAX_PARSED_BODY_BYTES) {
    try {
      let changed = false;
      const walk = (node: unknown): unknown => {
        if (Array.isArray(node)) return node.map(walk);
        if (!isRecord(node)) return node;
        const out: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(node)) {
          if (isCredential(key) && value !== null && value !== "") {
            changed = true;
            out[key] = REDACTED;
          } else out[key] = walk(value);
        }
        return out;
      };
      const redacted = walk(JSON.parse(body));
      return changed ? JSON.stringify(redacted) : body;
    } catch {
      // Not valid JSON: redacted by pattern below.
    }
  }
  return body.replace(/"((?:[^"\\]|\\.){1,256})"(\s*:\s*)("(?:[^"\\]|\\.)*"|[^\s,}\]"]+)/g, (whole, key: string, colon: string) =>
    isCredential(key) ? `"${key}"${colon}"${REDACTED}"` : whole
  );
}

type MultipartPart = { head: string; name: string | null; file: boolean; content: string; trailing: string };

function multipartBoundary(contentType: string): string | null {
  const match = /boundary=(?:"([^"]{1,200})"|([^;\s]{1,200}))/i.exec(contentType);
  return match ? (match[1] ?? match[2]) : null;
}

/** The body split at its boundary: the text around the parts, and each part. */
function multipartParts(body: string, boundary: string): { segments: string[]; parts: Map<number, MultipartPart> } {
  const segments = body.split(`--${boundary}`);
  const parts = new Map<number, MultipartPart>();
  segments.forEach((segment, index) => {
    if (index === 0 || segment.startsWith("--")) return;
    let headEnd = segment.indexOf("\r\n\r\n");
    let separator = 4;
    if (headEnd === -1) {
      headEnd = segment.indexOf("\n\n");
      separator = 2;
    }
    if (headEnd === -1) return;
    const head = segment.slice(0, headEnd + separator);
    let content = segment.slice(headEnd + separator);
    const trailing = content.endsWith("\r\n") ? "\r\n" : content.endsWith("\n") ? "\n" : "";
    content = content.slice(0, content.length - trailing.length);
    const disposition = /content-disposition:[^\r\n]*/i.exec(head)?.[0] ?? "";
    const name = /;\s*name="([^"]*)"/i.exec(disposition)?.[1] ?? /;\s*name=([^;\s]+)/i.exec(disposition)?.[1] ?? null;
    parts.set(index, { head, name, file: /;\s*filename\*?=/i.test(disposition), content, trailing });
  });
  return { segments, parts };
}

function sanitizeMultipart(body: string, boundary: string, isCredential: CredentialTest): string {
  const { segments, parts } = multipartParts(body, boundary);
  return segments
    .map((segment, index) => {
      const part = parts.get(index);
      if (!part) return segment;
      let content = part.content;
      if (part.file || looksBinary(content)) content = `[${formatBytes(sentBytes(content))} of file data not stored]`;
      else if (part.name !== null && isCredential(part.name)) content = REDACTED;
      return part.head + content + part.trailing;
    })
    .join(`--${boundary}`);
}

/** The body as a WAF event keeps it, before the size cut: credentials redacted, files and binary data left out. */
export function sanitizeRequestBody(body: string, contentType: string, isCredential: CredentialTest): string {
  if (!body) return body;
  const type = contentType.toLowerCase();
  const boundary = type.startsWith("multipart/") ? multipartBoundary(contentType) : null;
  if (boundary) return sanitizeMultipart(body, boundary, isCredential);
  if (looksBinary(body)) return `[${formatBytes(sentBytes(body))} of binary data not stored]`;
  if (type.includes("x-www-form-urlencoded")) return redactFormBody(body, isCredential);
  if (type.includes("json") || /^\s*[[{]/.test(body)) return redactJsonBody(body, isCredential);
  return body;
}

type RequestParts = { body: string; contentType: string; uri: string; header: (name: string) => string | null };

/** The value at a Coraza JSON argument path (json.a.0.b); keys holding dots are tried whole too. */
function jsonValueAt(node: unknown, segments: string[]): unknown {
  if (segments.length === 0) return node;
  if (Array.isArray(node)) {
    const index = Number(segments[0]);
    return Number.isInteger(index) && index >= 0 && index < node.length ? jsonValueAt(node[index], segments.slice(1)) : undefined;
  }
  if (!isRecord(node)) return undefined;
  for (let take = 1; take <= segments.length; take++) {
    const key = segments.slice(0, take).join(".");
    if (Object.hasOwn(node, key)) {
      const found = jsonValueAt(node[key], segments.slice(take));
      if (found !== undefined) return found;
    }
  }
  return undefined;
}

function scalarText(value: unknown): string | null {
  if (value === undefined) return null;
  if (value === null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function queryValue(uri: string, name: string): string | null {
  const at = uri.indexOf("?");
  if (at === -1) return null;
  const pairs = formPairs(uri.slice(at + 1).split("#")[0]);
  return (pairs.find(([key]) => key === name) ?? pairs.find(([key]) => key.toLowerCase() === name.toLowerCase()))?.[1] ?? null;
}

function bodyArgument(request: RequestParts, name: string, parsedJson: () => unknown): string | null {
  const { body, contentType } = request;
  if (!body) return null;
  const type = contentType.toLowerCase();
  if (name.startsWith("json.") || name === "json") {
    const value = jsonValueAt(parsedJson(), name === "json" ? [] : name.slice(5).split("."));
    return scalarText(value);
  }
  if (type.includes("x-www-form-urlencoded")) {
    const pairs = formPairs(body);
    return (pairs.find(([key]) => key === name) ?? pairs.find(([key]) => key.toLowerCase() === name.toLowerCase()))?.[1] ?? null;
  }
  const boundary = type.startsWith("multipart/") ? multipartBoundary(contentType) : null;
  if (boundary) {
    for (const part of multipartParts(body, boundary).parts.values()) {
      if (!part.file && part.name === name) return part.content;
    }
  }
  return null;
}

/** The value of the variable a rule matched, from the request; null when it cannot be told or must not be kept. */
function variableValue(variable: string, request: RequestParts, sanitizedBody: () => string, parsedJson: () => unknown, isCredential: CredentialTest): string | null {
  const colon = variable.indexOf(":");
  const collection = (colon === -1 ? variable : variable.slice(0, colon)).toUpperCase();
  const key = colon === -1 ? "" : variable.slice(colon + 1);
  if (key && isCredential(key)) return null;
  const query = request.uri.includes("?") ? request.uri.slice(request.uri.indexOf("?") + 1) : "";
  switch (collection) {
    case "REQUEST_HEADERS":
      return key ? request.header(key.toLowerCase()) : null;
    case "ARGS_GET":
      return key ? queryValue(request.uri, key) : null;
    case "ARGS_POST":
      return key ? bodyArgument(request, key, parsedJson) : null;
    case "ARGS":
      return key ? (bodyArgument(request, key, parsedJson) ?? queryValue(request.uri, key)) : null;
    case "REQUEST_BODY":
      return sanitizedBody() || null;
    case "REQUEST_URI":
    case "REQUEST_URI_RAW":
      return request.uri || null;
    case "QUERY_STRING":
      return query || null;
    default:
      return null;
  }
}

/** The value, or a window of it with the match near its start. */
function excerpt(value: string, span: MatchSpan | null): { text: string; offset: number } {
  if (value.length <= MAX_VALUE_CHARS) return { text: value, offset: 0 };
  let from = span ? Math.max(0, span.start - CONTEXT_BEFORE) : 0;
  if (span && span.end - from > MAX_VALUE_CHARS) from = span.start;
  return { text: value.slice(from, from + MAX_VALUE_CHARS), offset: from };
}

function matchedValuesOf(messages: unknown, request: RequestParts, sanitizedBody: () => string, isCredential: CredentialTest): WafMatchedValue[] {
  if (!Array.isArray(messages) || messages.length === 0) return [];
  let rules;
  try {
    rules = explainWafAuditRecord(JSON.stringify({ transaction: {}, messages })).rules;
  } catch {
    return [];
  }
  let json: unknown;
  let jsonRead = false;
  const parsedJson = () => {
    if (!jsonRead) {
      jsonRead = true;
      try {
        json = utf8Length(request.body) <= MAX_PARSED_BODY_BYTES ? JSON.parse(request.body) : undefined;
      } catch {
        json = undefined;
      }
    }
    return json;
  };
  const values: WafMatchedValue[] = [];
  const seen = new Set<string>();
  for (const rule of rules) {
    if (values.length >= MAX_MATCHED_VALUES) break;
    const split = rule.matchedData ? splitMatchedLogData(rule.matchedData) : null;
    if (!split || !split.found) continue;
    const key = `${rule.ruleId}\n${split.variable}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const value = variableValue(split.variable, request, sanitizedBody, parsedJson, isCredential);
    if (value === null) continue;
    const span = locateMatch(value, split.found);
    const { text, offset } = excerpt(value, span);
    values.push({
      ruleId: rule.ruleId,
      variable: split.variable,
      value: text,
      offset,
      length: value.length,
      start: span ? span.start - offset : -1,
      end: span ? Math.min(span.end - offset, text.length) : -1,
    });
  }
  return values;
}

/**
 * Cleans and cuts the request body of an audit record about to be stored,
 * and keeps the matched values (see the top of this file). `record` is the
 * parser's copy, its headers, URI and messages already redacted.
 */
export function captureAuditRequest(record: Record<string, unknown>, isCredential: CredentialTest): void {
  const tx = record.transaction;
  const request = isRecord(tx) && isRecord(tx.request) ? tx.request : null;
  if (!request) return;
  const header = headerLookup(request.headers);
  const parts: RequestParts = {
    body: typeof request.body === "string" ? request.body : "",
    contentType: header("content-type") ?? "",
    uri: typeof request.uri === "string" ? request.uri : "",
    header,
  };
  let sanitized: string | null = null;
  const sanitizedBody = () => (sanitized ??= sanitizeRequestBody(parts.body, parts.contentType, isCredential));
  const matchedValues = matchedValuesOf(record.messages, parts, sanitizedBody, isCredential);
  // Nothing to keep: the record stays as Coraza wrote it.
  if (!parts.body && matchedValues.length === 0) return;
  const stored = truncateUtf8(sanitizedBody(), MAX_STORED_BODY_BYTES);
  if (typeof request.body === "string") request.body = stored;
  const capture: WafRequestCapture = {
    bodyBytes: sentBytes(parts.body),
    bodyStoredBytes: utf8Length(stored),
    bodyCut: stored.length < sanitizedBody().length,
    matchedValues,
  };
  record[WAF_CAPTURE_KEY] = capture;
}

// ── Reading it back ─────────────────────────────────────────────────────────

export type WafRequestView = {
  /** e.g. "POST /upload?x=1 HTTP/2.0". */
  requestLine: string;
  headers: Array<[string, string]>;
  body: string;
  /** Content-Length the client sent, when it did. */
  contentLength: number | null;
  /** Null when there was no body and no matched value to keep, or the event predates keeping them. */
  capture: WafRequestCapture | null;
};

const MAX_HEADERS = 200;
const MAX_HEADER_VALUE = 8192;

function nonNegative(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function captureOf(value: unknown): WafRequestCapture | null {
  if (!isRecord(value)) return null;
  const bodyBytes = nonNegative(value.bodyBytes);
  const bodyStoredBytes = nonNegative(value.bodyStoredBytes);
  if (bodyBytes === null || bodyStoredBytes === null) return null;
  const matchedValues: WafMatchedValue[] = [];
  for (const item of Array.isArray(value.matchedValues) ? value.matchedValues.slice(0, MAX_MATCHED_VALUES) : []) {
    if (!isRecord(item) || typeof item.variable !== "string" || typeof item.value !== "string") continue;
    const ruleId = nonNegative(item.ruleId);
    const offset = nonNegative(item.offset);
    const length = nonNegative(item.length);
    if (ruleId === null || offset === null || length === null) continue;
    const value = item.value.slice(0, MAX_VALUE_CHARS);
    const start = typeof item.start === "number" ? item.start : -1;
    const end = typeof item.end === "number" ? item.end : -1;
    const located = Number.isSafeInteger(start) && Number.isSafeInteger(end) && start >= 0 && start <= end && end <= value.length;
    matchedValues.push({ ruleId, variable: item.variable.slice(0, 512), value, offset, length, start: located ? start : -1, end: located ? end : -1 });
  }
  return { bodyBytes, bodyStoredBytes, bodyCut: value.bodyCut === true, matchedValues };
}

/** The full request of a stored audit record (waf_events.raw_data); null when it is not one. */
export function wafRequestViewOf(rawData: string | null | undefined): WafRequestView | null {
  if (!rawData) return null;
  let record: unknown;
  try {
    record = JSON.parse(rawData);
  } catch {
    return null;
  }
  if (!isRecord(record) || !isRecord(record.transaction)) return null;
  const request = isRecord(record.transaction.request) ? record.transaction.request : {};
  const method = typeof request.method === "string" ? request.method.slice(0, 32) : "";
  const uri = typeof request.uri === "string" ? request.uri.slice(0, 16_384) : "";
  const protocol =
    typeof request.protocol === "string" && request.protocol
      ? request.protocol.slice(0, 16)
      : typeof request.http_version === "string" && request.http_version
        ? `HTTP/${request.http_version.slice(0, 8)}`
        : "";

  const headers: Array<[string, string]> = [];
  if (isRecord(request.headers)) {
    // Coraza writes the headers sorted by name; Host leads, as on the wire.
    const entries = Object.entries(request.headers).sort(([a], [b]) => Number(b.toLowerCase() === "host") - Number(a.toLowerCase() === "host"));
    for (const [name, values] of entries) {
      for (const value of Array.isArray(values) ? values : [values]) {
        if (typeof value !== "string" || headers.length >= MAX_HEADERS) continue;
        headers.push([name.slice(0, 256), value.slice(0, MAX_HEADER_VALUE)]);
      }
    }
  }
  const lengthHeader = headers.find(([name]) => name.toLowerCase() === "content-length")?.[1];
  const contentLength = lengthHeader && /^\d{1,15}$/.test(lengthHeader.trim()) ? Number(lengthHeader.trim()) : null;
  const body = typeof request.body === "string" ? truncateUtf8(request.body, MAX_STORED_BODY_BYTES) : "";
  return {
    requestLine: [method, uri, protocol].filter(Boolean).join(" "),
    headers,
    body,
    contentLength,
    capture: captureOf(record[WAF_CAPTURE_KEY]),
  };
}
