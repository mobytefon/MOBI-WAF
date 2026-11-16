"use server";

import { revalidatePath } from "next/cache";
import { requirePermission } from "@/src/lib/auth";
import { applyCaddyConfig } from "@/src/lib/caddy";
import { CaddyApplyError } from "@/src/lib/caddy-apply-error";
import { logAuditEvent } from "@/src/lib/audit";
import { withSettingsUpdateLock } from "@/src/lib/settings-update-lock";
import { clearSetting, getSetting, setSetting } from "@/src/lib/settings";
import { crowdSecActionError } from "@/src/lib/crowdsec/api";
import { banFromDashboard, unbanAddress, unbanDecision } from "@/src/lib/crowdsec/decisions";
import { decisionsForAddress, getAlert, type CrowdSecAlert, type CrowdSecDecision } from "@/src/lib/crowdsec/lapi-client";
import { CROWDSEC_SETTINGS_KEY, crowdSecSettingsError, saveCrowdSecSettings, type CrowdSecSettings } from "@/src/lib/crowdsec/settings";
import {
  createCrowdSecWhitelist,
  deleteCrowdSecWhitelist,
  reapplyCrowdSecWhitelists,
  updateCrowdSecWhitelist,
  type CrowdSecWhitelist,
  type CrowdSecWhitelistInput,
} from "@/src/lib/models/crowdsec-whitelists";

export type CrowdSecActionResult<T> = { ok: true; value: T } | { ok: false; error: string };

async function run<T>(operation: () => Promise<T>, fallback: string): Promise<CrowdSecActionResult<T>> {
  try {
    const value = await operation();
    revalidatePath("/crowdsec", "layout");
    return { ok: true, value };
  } catch (error) {
    const message = crowdSecActionError(error, "");
    if (message) return { ok: false, error: message };
    console.error("[crowdsec] action failed:", error instanceof Error ? error.name : typeof error);
    return { ok: false, error: fallback };
  }
}

// ── Reads ───────────────────────────────────────────────────────────────────

export async function getCrowdSecAlertAction(id: number): Promise<CrowdSecActionResult<CrowdSecAlert>> {
  await requirePermission("crowdsec:read");
  return run(() => getAlert(id), "The alert could not be read");
}

export async function lookupCrowdSecAddressAction(address: string): Promise<CrowdSecActionResult<CrowdSecDecision[]>> {
  await requirePermission("crowdsec:read");
  return run(() => decisionsForAddress(address), "The address could not be looked up");
}

// ── Decisions ───────────────────────────────────────────────────────────────

export type BanInput = { target: string; type: "ban" | "captcha" | "throttle"; duration: string; reason: string; bypassWhitelist?: boolean };

export async function banCrowdSecAction(input: BanInput): Promise<CrowdSecActionResult<{ alertId: number | null }>> {
  const session = await requirePermission("crowdsec:write");
  return run(() => banFromDashboard(input, Number(session.user.id)), "The decision could not be added");
}

export async function deleteCrowdSecDecisionAction(id: number): Promise<CrowdSecActionResult<number>> {
  const session = await requirePermission("crowdsec:write");
  return run(() => unbanDecision(id, Number(session.user.id)), "The decision could not be deleted");
}

export async function unbanCrowdSecAddressAction(address: string): Promise<CrowdSecActionResult<number>> {
  const session = await requirePermission("crowdsec:write");
  return run(() => unbanAddress(address, Number(session.user.id)), "The decisions could not be deleted");
}

// ── Whitelists ──────────────────────────────────────────────────────────────

export async function createCrowdSecWhitelistAction(input: CrowdSecWhitelistInput): Promise<CrowdSecActionResult<CrowdSecWhitelist>> {
  const session = await requirePermission("crowdsec:write");
  return run(() => createCrowdSecWhitelist(input, Number(session.user.id)), "The whitelist could not be saved");
}

export async function updateCrowdSecWhitelistAction(id: number, input: CrowdSecWhitelistInput): Promise<CrowdSecActionResult<CrowdSecWhitelist>> {
  const session = await requirePermission("crowdsec:write");
  return run(() => updateCrowdSecWhitelist(id, input, Number(session.user.id)), "The whitelist could not be saved");
}

export async function deleteCrowdSecWhitelistAction(id: number): Promise<CrowdSecActionResult<null>> {
  const session = await requirePermission("crowdsec:write");
  return run(async () => {
    await deleteCrowdSecWhitelist(id, Number(session.user.id));
    return null;
  }, "The whitelist could not be deleted");
}

export async function reapplyCrowdSecWhitelistsAction(): Promise<CrowdSecActionResult<number>> {
  const session = await requirePermission("crowdsec:write");
  return run(() => reapplyCrowdSecWhitelists(Number(session.user.id)), "The whitelists could not be applied again");
}

// ── Settings ────────────────────────────────────────────────────────────────

/**
 * Saves the global CrowdSec settings and applies the Caddy configuration;
 * when Caddy refuses it, the previous settings are put back.
 */
export async function saveCrowdSecSettingsAction(input: CrowdSecSettings): Promise<CrowdSecActionResult<null>> {
  const session = await requirePermission("crowdsec:write");
  const userId = Number(session.user.id);
  const value = { enabled: input?.enabled, apply_to_all_hosts: input?.apply_to_all_hosts, ticker_interval: input?.ticker_interval, lapi_timeout: input?.lapi_timeout };
  const problem = crowdSecSettingsError(value);
  if (problem) return { ok: false, error: problem };
  return await withSettingsUpdateLock(async () => {
    const previous = await getSetting<unknown>(CROWDSEC_SETTINGS_KEY);
    await saveCrowdSecSettings(value as CrowdSecSettings);
    try {
      await applyCaddyConfig();
    } catch (error) {
      if (previous === null) await clearSetting(CROWDSEC_SETTINGS_KEY);
      else await setSetting(CROWDSEC_SETTINGS_KEY, previous);
      await applyCaddyConfig().catch(() => undefined);
      const detail = error instanceof CaddyApplyError ? `: ${error.message}` : "";
      return { ok: false as const, error: `Caddy did not take the configuration, so the CrowdSec settings were put back${detail}` };
    }
    await logAuditEvent({ userId, action: "update", entityType: "setting", summary: "Updated the CrowdSec settings", data: value });
    revalidatePath("/crowdsec", "layout");
    return { ok: true as const, value: null };
  });
}
