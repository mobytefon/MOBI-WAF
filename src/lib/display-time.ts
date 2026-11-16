/**
 * MOBI-WAF shows times in Vietnam time (Asia/Ho_Chi_Minh, UTC+7, no daylight
 * saving), not UTC. Pages that format with getUTC*() call `zoned()` first:
 * the returned Date's UTC fields read Vietnam wall-clock time. Pure; safe on
 * the server and the client, so server and browser render the same text.
 */

export const DISPLAY_TIME_ZONE = "Asia/Ho_Chi_Minh";
/** The label shown next to times, e.g. "14:05 UTC+7". */
export const DISPLAY_TIME_ZONE_LABEL = "UTC+7";
export const DISPLAY_OFFSET_SECONDS = 7 * 3600;
export const DISPLAY_OFFSET_MS = DISPLAY_OFFSET_SECONDS * 1000;

type DateInput = Date | number | string;

/** A Date shifted by +7 h: read it with getUTC*() to get Vietnam time. Never send it anywhere. */
export function zoned(value: DateInput): Date {
  const ms = value instanceof Date ? value.getTime() : typeof value === "number" ? value : Date.parse(value);
  return new Date(ms + DISPLAY_OFFSET_MS);
}

/** "YYYY-MM-DDTHH:mm" of a Unix time in Vietnam time (an <input type="datetime-local"> value). */
export function toZonedInputValue(seconds: number): string {
  return zoned(seconds * 1000).toISOString().slice(0, 16);
}

/** The Unix time of a datetime-local value read as Vietnam time, or null. */
export function fromZonedInputValue(value: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value)) return null;
  const ms = Date.parse(`${value.length === 16 ? `${value}:00` : value}Z`);
  return Number.isNaN(ms) ? null : Math.floor((ms - DISPLAY_OFFSET_MS) / 1000);
}
