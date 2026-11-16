/**
 * Hands the managed whitelists to the crowdsec container. The web service
 * and the container share a volume (CROWDSEC_MANAGED_DIR here, /ingressi
 * there; docker-compose.crowdsec.yml). When the whitelists' generation is
 * newer than the one in desired/generation, their files are written to
 * desired/ and the generation last; the container's watcher then checks
 * them with `crowdsec -t`, reloads CrowdSec and writes status/result.json.
 * Runs on the leader (src/instrumentation.ts), every few seconds; it does
 * nothing when the directory is missing.
 */
import { existsSync } from "node:fs";
import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { readCrowdSecWhitelistState } from "../models/crowdsec-whitelists";
import { onShutdown } from "../shutdown";
import { getCrowdSecEnvironment } from "./config";
import { renderWhitelists } from "./whitelist-render";

export const MANAGED_SYNC_INTERVAL_MS = 5_000;
const FILE_PATTERN = /^zz-ingressi-\d+\.yaml$/;

export type ManagedApplyResult = { generation: number; ok: boolean; message: string; at: string };

export type ManagedStatus = {
  /** The shared directory exists and the job can write to it. */
  available: boolean;
  /** The generation handed to CrowdSec (desired/generation). */
  written: number | null;
  /** What the watcher reported for the last generation it applied. */
  result: ManagedApplyResult | null;
  /** The watcher's periodic snapshot (bouncers, machines, hub), as it wrote it. */
  snapshot: { at?: string; bouncers?: unknown; machines?: unknown; hub?: unknown } | null;
};

function managedDir(): string | null {
  const dir = getCrowdSecEnvironment()?.managedDir;
  return dir && existsSync(dir) ? dir : null;
}

async function writeAtomic(path: string, content: string): Promise<void> {
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, content, { mode: 0o644 });
  await rename(temporary, path);
}

async function readJsonFile<T>(path: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch {
    return null;
  }
}

async function readWrittenGeneration(dir: string): Promise<number | null> {
  try {
    const value = Number((await readFile(join(dir, "desired", "generation"), "utf8")).trim());
    return Number.isSafeInteger(value) ? value : null;
  } catch {
    return null;
  }
}

/** Writes the whitelists when their generation is not the one written yet. Returns the generation written, or null. */
export async function syncManagedWhitelists(force = false): Promise<number | null> {
  const dir = managedDir();
  if (!dir) return null;
  const { generation, entries } = await readCrowdSecWhitelistState();
  const written = await readWrittenGeneration(dir);
  if (!force && written === generation) return null;

  const desired = join(dir, "desired");
  const whitelistDir = join(desired, "whitelists");
  await mkdir(whitelistDir, { recursive: true });
  const rendered = renderWhitelists(entries);
  for (const name of await readdir(whitelistDir)) {
    if (FILE_PATTERN.test(name) && !(name in rendered.files)) await rm(join(whitelistDir, name), { force: true });
  }
  for (const [name, content] of Object.entries(rendered.files)) await writeAtomic(join(whitelistDir, name), content);
  await writeAtomic(join(desired, "allowlist.txt"), rendered.allowlist);
  await writeAtomic(join(desired, "generation"), `${generation}\n`);
  return generation;
}

export async function readManagedStatus(): Promise<ManagedStatus> {
  const dir = managedDir();
  if (!dir) return { available: false, written: null, result: null, snapshot: null };
  const [written, result, snapshot] = await Promise.all([
    readWrittenGeneration(dir),
    readJsonFile<ManagedApplyResult>(join(dir, "status", "result.json")),
    readJsonFile<ManagedStatus["snapshot"]>(join(dir, "status", "snapshot.json")),
  ]);
  return { available: true, written, result, snapshot };
}

type SyncState = { interval: ReturnType<typeof setInterval> | null; running: boolean };
const store = globalThis as typeof globalThis & { __ingressiCrowdSecManagedSync?: SyncState };
const state = (store.__ingressiCrowdSecManagedSync ??= { interval: null, running: false });

async function tick(): Promise<void> {
  if (state.running) return;
  state.running = true;
  try {
    const generation = await syncManagedWhitelists();
    if (generation !== null) console.log(`[crowdsec] Whitelists generation ${generation} handed to CrowdSec`);
  } catch (error) {
    console.error("[crowdsec] Writing the managed whitelists failed:", error instanceof Error ? error.name : typeof error);
  } finally {
    state.running = false;
  }
}

export function startCrowdSecManagedSync(): void {
  if (state.interval || !getCrowdSecEnvironment()?.managedDir) return;
  state.interval = setInterval(() => void tick(), MANAGED_SYNC_INTERVAL_MS);
  state.interval.unref?.();
  void tick();
  onShutdown("stopping the CrowdSec whitelist sync", stopCrowdSecManagedSync);
}

export function stopCrowdSecManagedSync(): void {
  if (state.interval) clearInterval(state.interval);
  state.interval = null;
}
