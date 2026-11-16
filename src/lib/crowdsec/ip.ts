/** Address arithmetic for whitelist checks: does a range contain an address or another range. */
import { isIP } from "node:net";

type Parsed = { family: 4 | 6; value: bigint; bits: number };

function v4(text: string): bigint {
  return text.split(".").reduce((acc, part) => (acc << 8n) | BigInt(Number(part)), 0n);
}

function v6(text: string): bigint {
  let address = text;
  // An embedded IPv4 tail (::ffff:1.2.3.4) becomes two groups.
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(address);
  if (tail) {
    const n = v4(tail[1]);
    address = `${address.slice(0, -tail[1].length)}${(n >> 16n).toString(16)}:${(n & 0xffffn).toString(16)}`;
  }
  const [head, rest] = address.split("::");
  const left = head ? head.split(":") : [];
  const right = rest !== undefined && rest ? rest.split(":") : [];
  const groups = rest === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  return groups.reduce((acc, group) => (acc << 16n) | BigInt(parseInt(group || "0", 16)), 0n);
}

/** An address or CIDR range, or null when it is neither. */
export function parseAddressOrRange(text: string): Parsed | null {
  const [address, prefix, extra] = text.trim().split("/");
  if (extra !== undefined) return null;
  const family = isIP(address);
  if (family !== 4 && family !== 6) return null;
  const max = family === 4 ? 32 : 128;
  const bits = prefix === undefined ? max : /^\d{1,3}$/.test(prefix) ? Number(prefix) : NaN;
  if (!Number.isInteger(bits) || bits < 0 || bits > max) return null;
  return { family, value: family === 4 ? v4(address) : v6(address), bits };
}

/** Whether `outer` (a range or address) contains `inner` (an address or range) entirely. */
export function rangeContains(outer: string, inner: string): boolean {
  const a = parseAddressOrRange(outer);
  const b = parseAddressOrRange(inner);
  if (!a || !b || a.family !== b.family || b.bits < a.bits) return false;
  const width = BigInt(a.family === 4 ? 32 : 128);
  const shift = width - BigInt(a.bits);
  return a.value >> shift === b.value >> shift;
}
