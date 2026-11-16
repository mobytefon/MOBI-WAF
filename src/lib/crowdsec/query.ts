/** Alert filters from URL search parameters (the REST route and the Alerts page). */
import { ApiValidationError } from "../api-errors";
import { isCrowdSecDuration, parseCrowdSecTarget, type AlertQuery } from "./lapi-client";

const SCENARIO = /^[A-Za-z0-9_./:-]{1,200}$/;
const ORIGIN = /^[A-Za-z0-9_.:-]{1,100}$/;

export function parseAlertQuery(params: URLSearchParams): AlertQuery {
  const query: AlertQuery = {};
  const since = params.get("since");
  if (since) {
    if (!isCrowdSecDuration(since)) throw new ApiValidationError('since must be a duration such as "24h"');
    query.since = since;
  }
  const ip = params.get("ip");
  if (ip) {
    const target = parseCrowdSecTarget(ip);
    if (!target) throw new ApiValidationError("ip must be an IP address or a CIDR range");
    if (target.scope === "Ip") query.ip = target.value;
    else query.range = target.value;
  }
  const scenario = params.get("scenario");
  if (scenario) {
    if (!SCENARIO.test(scenario)) throw new ApiValidationError("scenario has characters a scenario name cannot have");
    query.scenario = scenario;
  }
  const origin = params.get("origin");
  if (origin) {
    if (!ORIGIN.test(origin)) throw new ApiValidationError("origin has characters an origin cannot have");
    query.origin = origin;
  }
  const decision = params.get("has_active_decision");
  if (decision === "true" || decision === "false") query.hasActiveDecision = decision === "true";
  const limit = params.get("limit");
  if (limit) {
    const value = Number(limit);
    if (!Number.isInteger(value) || value < 1 || value > 10_000) throw new ApiValidationError("limit must be from 1 to 10000");
    query.limit = value;
  }
  return query;
}
