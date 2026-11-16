/**
 * Decisions as the dashboard lists them: the active decisions of the LAPI's
 * alerts (CrowdSec's own and manual ones; the community blocklist only by
 * lookup), flattened with the alert they came from. Adding one first checks
 * the managed whitelists, as `cscli decisions add` checks allowlists.
 */
import { logAuditEvent } from "../audit";
import { ApiClientError } from "../api-errors";
import { addDecision, deleteDecision, deleteDecisionsFor, listAlerts, type CrowdSecAlert, type NewDecision } from "./lapi-client";
import { whitelistsCovering } from "../models/crowdsec-whitelists";

export type ActiveDecision = {
  id: number;
  alertId: number;
  origin: string;
  type: string;
  scope: string;
  value: string;
  duration: string;
  until: string | null;
  scenario: string;
  reason: string | null;
  country: string | null;
  asName: string | null;
  simulated: boolean;
};

/** Flattens alerts into their decisions, newest alert first, without duplicates. */
export function flattenDecisions(alerts: readonly CrowdSecAlert[]): ActiveDecision[] {
  const seen = new Set<number>();
  const out: ActiveDecision[] = [];
  for (const alert of alerts) {
    for (const decision of alert.decisions ?? []) {
      if (seen.has(decision.id)) continue;
      seen.add(decision.id);
      out.push({
        id: decision.id,
        alertId: alert.id,
        origin: decision.origin,
        type: decision.type,
        scope: decision.scope,
        value: decision.value,
        duration: decision.duration,
        until: decision.until ?? null,
        scenario: decision.scenario || alert.scenario,
        reason: alert.message ?? null,
        country: alert.source?.cn ?? null,
        asName: alert.source?.as_name ?? null,
        simulated: Boolean(decision.simulated),
      });
    }
  }
  return out;
}

export async function listActiveDecisions(options: { origin?: string; limit?: number } = {}): Promise<ActiveDecision[]> {
  const alerts = await listAlerts({ hasActiveDecision: true, origin: options.origin, limit: options.limit ?? 2_000 });
  return flattenDecisions(alerts);
}

/**
 * Adds a decision from the dashboard. An address a whitelist covers is
 * refused unless `bypassWhitelist` is set (the LAPI does not check
 * whitelists for decisions sent with an alert).
 */
export async function banFromDashboard(
  input: NewDecision & { bypassWhitelist?: boolean },
  actorUserId: number | null
): Promise<{ alertId: number | null }> {
  if (!input.bypassWhitelist) {
    const covering = await whitelistsCovering(input.target);
    if (covering.length > 0) {
      throw new ApiClientError(
        `${input.target} is whitelisted (${covering.map((entry) => entry.name).join(", ")}); confirm to ban it anyway`,
        409
      );
    }
  }
  const alertId = await addDecision(input);
  await logAuditEvent({
    userId: actorUserId,
    action: "create",
    entityType: "crowdsec_decision",
    summary: `Added a CrowdSec ${input.type} decision for ${input.target} (${input.duration})`,
    data: { target: input.target, type: input.type, duration: input.duration, reason: input.reason, bypassWhitelist: Boolean(input.bypassWhitelist) },
  });
  return { alertId };
}

export async function unbanDecision(id: number, actorUserId: number | null): Promise<number> {
  const deleted = await deleteDecision(id);
  await logAuditEvent({ userId: actorUserId, action: "delete", entityType: "crowdsec_decision", summary: `Deleted CrowdSec decision ${id}`, data: { id, deleted } });
  return deleted;
}

export async function unbanAddress(address: string, actorUserId: number | null): Promise<number> {
  const deleted = await deleteDecisionsFor(address);
  await logAuditEvent({
    userId: actorUserId,
    action: "delete",
    entityType: "crowdsec_decision",
    summary: `Deleted every CrowdSec decision for ${address.trim()}`,
    data: { target: address.trim(), deleted },
  });
  return deleted;
}
