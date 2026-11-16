/**
 * OpenAPI paths and schemas of the CrowdSec endpoints (app/api/v1/crowdsec),
 * spread into app/api/v1/openapi.json/route.ts. Kinds come from the
 * whitelist model, so they cannot drift from what the API accepts.
 */
import { WHITELIST_KINDS } from "./models/crowdsec-whitelists";

const TAG = "CrowdSec";

export const CROWDSEC_OPENAPI_TAG = {
  name: TAG,
  description:
    "CrowdSec: the bouncer in Caddy blocks client addresses CrowdSec has decisions for (its scenarios on Caddy's access log, " +
    "manual bans and the community blocklist). Alerts and decisions are read from the CrowdSec Local API; whitelists are " +
    "managed here and applied by CrowdSec. These endpoints answer 404 CROWDSEC_NOT_CONFIGURED when CrowdSec is not set up " +
    "on the instance, and 502 CROWDSEC_UNAVAILABLE when the Local API cannot be reached.",
};

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const json = (schema: unknown) => ({ "application/json": { schema } });
const ok = (description: string, schema: unknown) => ({ description, content: json(schema) });
const errors = (...codes: string[]) => {
  const map: Record<string, unknown> = {
    "400": { $ref: "#/components/responses/BadRequest" },
    "401": { $ref: "#/components/responses/Unauthorized" },
    "403": { $ref: "#/components/responses/Forbidden" },
    "404": { $ref: "#/components/responses/NotFound" },
    "409": { $ref: "#/components/responses/Conflict" },
  };
  return Object.fromEntries(codes.map((code) => [code, map[code]]));
};
const unavailable = { "502": { description: "The CrowdSec Local API could not be reached or refused the request", content: json(ref("Error")) } };
const idPath = { $ref: "#/components/parameters/IdPath" };
const query = (name: string, description: string, schema: unknown = { type: "string" }) => ({ name, in: "query", required: false, schema, description });
const body = (schema: unknown) => ({ required: true, content: json(schema) });

const READ = "Needs crowdsec:read.";
const WRITE = "Needs crowdsec:write.";

export const CROWDSEC_OPENAPI_PATHS = {
  "/api/v1/crowdsec/status": {
    get: {
      tags: [TAG],
      summary: "CrowdSec status",
      description: `Whether CrowdSec is configured and its Local API answers, the global settings, active decisions by origin, how far the whitelists are applied and which hosts use the bouncer. ${READ}`,
      operationId: "getCrowdSecStatus",
      responses: { "200": ok("Status", ref("CrowdSecStatus")), ...errors("401", "403") },
    },
  },
  "/api/v1/crowdsec/alerts": {
    get: {
      tags: [TAG],
      summary: "List CrowdSec alerts",
      description: `Alerts newest first, the community blocklist left out. ${READ}`,
      operationId: "listCrowdSecAlerts",
      parameters: [
        query("since", 'How far back, as a duration such as "24h".'),
        query("ip", "Only alerts of this source address or CIDR range."),
        query("scenario", "Only alerts of this scenario, e.g. crowdsecurity/http-probing."),
        query("origin", "Only alerts with decisions of this origin."),
        query("has_active_decision", "Only alerts with (true) or without (false) an active decision.", { type: "boolean" }),
        query("limit", "At most this many alerts (1 to 10000, default 100).", { type: "integer", minimum: 1, maximum: 10000 }),
      ],
      responses: { "200": ok("Alerts", { type: "array", items: ref("CrowdSecAlert") }), ...errors("400", "401", "403", "404"), ...unavailable },
    },
  },
  "/api/v1/crowdsec/alerts/{id}": {
    get: {
      tags: [TAG],
      summary: "Get a CrowdSec alert",
      description: `One alert with its events and decisions. ${READ}`,
      operationId: "getCrowdSecAlert",
      parameters: [idPath],
      responses: { "200": ok("Alert", ref("CrowdSecAlert")), ...errors("401", "403", "404"), ...unavailable },
    },
  },
  "/api/v1/crowdsec/decisions": {
    get: {
      tags: [TAG],
      summary: "List active CrowdSec decisions",
      description: `With \`ip\`: every active decision for that address or range, community blocklist included. Without: CrowdSec's own and manual decisions, optionally of one \`origin\`. ${READ}`,
      operationId: "listCrowdSecDecisions",
      parameters: [query("ip", "An address or CIDR range to look up."), query("origin", "Only decisions of this origin (crowdsec, cscli…).")],
      responses: { "200": ok("Decisions", { type: "array", items: ref("CrowdSecDecision") }), ...errors("400", "401", "403", "404"), ...unavailable },
    },
    post: {
      tags: [TAG],
      summary: "Add a CrowdSec decision",
      description: `Bans (or throttles) an address or range, like \`cscli decisions add\`. An address a whitelist covers is refused with 409 unless \`bypassWhitelist\` is true. Caddy picks it up at the bouncer's next pull. ${WRITE}`,
      operationId: "addCrowdSecDecision",
      requestBody: body(ref("CrowdSecDecisionInput")),
      responses: {
        "201": ok("Added", { type: "object", properties: { alertId: { type: ["integer", "null"] } } }),
        ...errors("400", "401", "403", "404", "409"),
        ...unavailable,
      },
    },
    delete: {
      tags: [TAG],
      summary: "Delete every CrowdSec decision for an address",
      description: `Unbans an address or range: every decision for it is deleted. ${WRITE}`,
      operationId: "deleteCrowdSecDecisionsForAddress",
      parameters: [{ ...query("ip", "The address or CIDR range."), required: true }],
      responses: { "200": ok("Deleted", ref("CrowdSecDeleted")), ...errors("400", "401", "403", "404"), ...unavailable },
    },
  },
  "/api/v1/crowdsec/decisions/{id}": {
    delete: {
      tags: [TAG],
      summary: "Delete a CrowdSec decision",
      description: WRITE,
      operationId: "deleteCrowdSecDecision",
      parameters: [idPath],
      responses: { "200": ok("Deleted", ref("CrowdSecDeleted")), ...errors("401", "403", "404"), ...unavailable },
    },
  },
  "/api/v1/crowdsec/whitelists": {
    get: {
      tags: [TAG],
      summary: "List CrowdSec whitelists",
      description: `The managed whitelists, their generation, and what CrowdSec reported for the last one it applied. ${READ}`,
      operationId: "listCrowdSecWhitelists",
      responses: { "200": ok("Whitelists", ref("CrowdSecWhitelistList")), ...errors("401", "403") },
    },
    post: {
      tags: [TAG],
      summary: "Create a CrowdSec whitelist",
      description: `CrowdSec applies it within seconds (\`crowdsec -t\`, then a reload); a whitelist CrowdSec refuses leaves the previous ones in place. ${WRITE}`,
      operationId: "createCrowdSecWhitelist",
      requestBody: body(ref("CrowdSecWhitelistInput")),
      responses: { "201": ok("Created", ref("CrowdSecWhitelist")), ...errors("400", "401", "403") },
    },
  },
  "/api/v1/crowdsec/whitelists/{id}": {
    put: {
      tags: [TAG],
      summary: "Replace a CrowdSec whitelist",
      description: WRITE,
      operationId: "updateCrowdSecWhitelist",
      parameters: [idPath],
      requestBody: body(ref("CrowdSecWhitelistInput")),
      responses: { "200": ok("Updated", ref("CrowdSecWhitelist")), ...errors("400", "401", "403", "404") },
    },
    delete: {
      tags: [TAG],
      summary: "Delete a CrowdSec whitelist",
      description: WRITE,
      operationId: "deleteCrowdSecWhitelist",
      parameters: [idPath],
      responses: { "200": ok("Deleted", { type: "object", properties: { ok: { type: "boolean" } } }), ...errors("401", "403", "404") },
    },
  },
  "/api/v1/crowdsec/whitelists/apply": {
    post: {
      tags: [TAG],
      summary: "Apply the CrowdSec whitelists again",
      description: `Hands the whitelists to CrowdSec again as a new generation. ${WRITE}`,
      operationId: "reapplyCrowdSecWhitelists",
      responses: { "202": ok("Handed over", { type: "object", properties: { generation: { type: "integer" } } }), ...errors("401", "403") },
    },
  },
};

const decision = {
  type: "object",
  properties: {
    id: { type: "integer" },
    origin: { type: "string", description: "crowdsec, cscli, CAPI (community blocklist) or lists:<name>" },
    type: { type: "string", description: "ban, captcha or throttle" },
    scope: { type: "string", description: "Ip or Range" },
    value: { type: "string" },
    duration: { type: "string" },
    scenario: { type: "string" },
    until: { type: "string" },
  },
};

export const CROWDSEC_OPENAPI_SCHEMAS = {
  CrowdSecSettings: {
    type: "object",
    required: ["enabled", "apply_to_all_hosts"],
    properties: {
      enabled: { type: "boolean", description: "Master switch: off means no host uses the bouncer." },
      apply_to_all_hosts: { type: "boolean", description: "Hosts without a CrowdSec setting of their own use the bouncer." },
      ticker_interval: { type: "string", description: 'How often the bouncer pulls decisions (5s to 1h, default "60s").' },
      lapi_timeout: { type: "string", description: 'Time limit of each bouncer request to CrowdSec (1s to 2m, default "10s").' },
    },
    additionalProperties: false,
  },
  CrowdSecHostConfig: {
    type: "object",
    description: "A proxy host's CrowdSec setting: enabled true or false; null or no `enabled` inherits apply_to_all_hosts.",
    properties: { enabled: { type: "boolean" } },
    additionalProperties: false,
  },
  CrowdSecStatus: {
    type: "object",
    properties: {
      configured: { type: "boolean" },
      settings: ref("CrowdSecSettings"),
      lapi: { type: ["object", "null"], properties: { ok: { type: "boolean" }, error: { type: "string" } } },
      activeDecisions: {
        type: ["object", "null"],
        properties: {
          local: { type: "integer" },
          community: { type: "integer" },
          lists: { type: "integer" },
          byOrigin: { type: "object", additionalProperties: { type: "integer" } },
        },
      },
      managed: { type: ["object", "null"] },
      hosts: {
        type: "array",
        items: {
          type: "object",
          properties: {
            id: { type: "integer" },
            name: { type: "string" },
            enabled: { type: "boolean" },
            mode: { type: "string", enum: ["inherit", "on", "off"] },
            protected: { type: "boolean" },
          },
        },
      },
    },
  },
  CrowdSecAlert: {
    type: "object",
    description: "An alert as the CrowdSec Local API returns it (the fields the dashboard uses are listed).",
    properties: {
      id: { type: "integer" },
      scenario: { type: "string" },
      message: { type: "string" },
      events_count: { type: "integer" },
      start_at: { type: "string" },
      stop_at: { type: "string" },
      simulated: { type: "boolean" },
      source: {
        type: "object",
        properties: {
          scope: { type: "string" },
          value: { type: "string" },
          ip: { type: "string" },
          range: { type: "string" },
          as_number: { type: "string" },
          as_name: { type: "string" },
          cn: { type: "string" },
        },
      },
      decisions: { type: ["array", "null"], items: decision },
      events: { type: ["array", "null"], items: { type: "object" } },
    },
  },
  CrowdSecDecision: decision,
  CrowdSecDecisionInput: {
    type: "object",
    required: ["value"],
    properties: {
      value: { type: "string", description: "An IP address or CIDR range." },
      type: { type: "string", enum: ["ban", "captcha", "throttle"], default: "ban" },
      duration: { type: "string", default: "4h", description: 'A duration such as "4h" or "168h".' },
      reason: { type: "string", maxLength: 500 },
      bypassWhitelist: { type: "boolean", default: false },
    },
  },
  CrowdSecDeleted: { type: "object", properties: { deleted: { type: "integer" } } },
  CrowdSecWhitelistInput: {
    type: "object",
    required: ["name", "kind", "values"],
    properties: {
      name: { type: "string", maxLength: 100 },
      kind: { type: "string", enum: [...WHITELIST_KINDS] },
      values: {
        oneOf: [{ type: "array", items: { type: "string" } }, { type: "string" }],
        description: "Addresses, CIDR ranges, AS numbers or country codes (a list, or one string split on commas and whitespace); one expression for kind expression.",
      },
      reason: { type: "string", maxLength: 300 },
      enabled: { type: "boolean", default: true },
    },
  },
  CrowdSecWhitelist: {
    type: "object",
    properties: {
      id: { type: "integer" },
      name: { type: "string" },
      kind: { type: "string", enum: [...WHITELIST_KINDS] },
      values: { type: "array", items: { type: "string" } },
      reason: { type: "string" },
      enabled: { type: "boolean" },
      createdBy: { type: ["integer", "null"] },
      createdAt: { type: "string" },
      updatedAt: { type: "string" },
    },
  },
  CrowdSecWhitelistList: {
    type: "object",
    properties: {
      generation: { type: "integer" },
      whitelists: { type: "array", items: ref("CrowdSecWhitelist") },
      written: { type: ["integer", "null"], description: "The generation handed to CrowdSec." },
      applied: {
        type: ["object", "null"],
        description: "What CrowdSec reported for the last generation it applied.",
        properties: { generation: { type: "integer" }, ok: { type: "boolean" }, message: { type: "string" }, at: { type: "string" } },
      },
    },
  },
};
