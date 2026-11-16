# CrowdSec

[CrowdSec](https://www.crowdsec.net/) adds a layer that blocks client addresses by what they do. It reads Caddy's access log, applies its scenarios (scanning, brute force, known CVE probes…) and decides to ban the addresses behind them. It also pulls the community blocklist: addresses other CrowdSec users have seen attacking.

The Caddy bouncer ([caddy-crowdsec-bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer), HTTP handler only) keeps every decision in memory, refreshing it in stream mode. On each host that uses it, the bouncer runs **first, before rate limiting and the WAF**. A blocked address gets a 403 (429 for a throttle decision) and costs no WAF inspection or upstream request. CrowdSec complements the WAF (Coraza/OWASP CRS) rather than replacing it.

## Setting it up

1. Generate three secrets and put them in `.env`:

   ```sh
   echo "CROWDSEC_BOUNCER_KEY=$(openssl rand -hex 32)" >> .env
   echo "CROWDSEC_MACHINE_PASSWORD=$(openssl rand -hex 32)" >> .env
   echo "CROWDSEC_DB_PASSWORD=$(openssl rand -hex 32)" >> .env
   ```

   `CROWDSEC_ENROLL_KEY` is optional: it enrolls the engine in the CrowdSec console. The community blocklist works without it.

2. Start the stack with the CrowdSec overlay:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.crowdsec.yml up -d --build
   ```

   Alternatively, set `COMPOSE_FILE=docker-compose.yml:docker-compose.crowdsec.yml` in `.env`. List other overlays such as `docker-compose.postgres.yml` before it. The overlay adds:
   - `crowdsec`: built from `docker/crowdsec/`. It reads `access.log` read-only from `CADDY_LOGS_DIR` (or the `caddy-logs` volume).
   - `crowdsec-db`: its own PostgreSQL, on a network only `crowdsec` joins.
   - The CrowdSec settings and the shared `crowdsec-managed` volume on the `web` service.

   No port is published, and nothing reaches the Docker socket.

3. In the dashboard, under **Settings → Logging**, turn access logging on in **JSON** format. CrowdSec's Caddy parser needs JSON. Without the access log, CrowdSec raises no alerts of its own, but the bouncer still blocks community blocklist and manual decisions.

4. Behind a load balancer or CDN, set **Host defaults → Trusted proxies**. Caddy then records, and the bouncer then checks, the visitor's address rather than the proxy's.

5. Open **Observe → Security events → CrowdSec → Settings**. Turn **CrowdSec on**, then choose:
   - **Apply to all hosts**, or
   - per host, in the host editor (**Security → CrowdSec**): *Global setting*, *On* or *Off*.

   Hosts are not affected until you do one of these.

Installed collections: `crowdsecurity/caddy`, `crowdsecurity/base-http-scenarios`, `crowdsecurity/http-cve`, `crowdsecurity/whitelist-good-actors`, plus the `crowdsecurity/geoip-enrich` parser (country and AS of each source).

## The CrowdSec pages

All of these need `crowdsec:read`. Changing anything needs `crowdsec:write`. A host's own CrowdSec mode is part of the host and needs `proxy_hosts:write`.

- **Dashboard**: alerts of the last 24 hours or 7 days by scenario over time, active decisions (CrowdSec's own and manual ones, and the community blocklist), how many hosts use the bouncer, and the top scenarios, sources, countries and networks.
- **Alerts**: alerts filtered by source address or range, scenario and origin, with each alert's events and decisions. *Ban* adds a decision for the source.
- **Decisions**: the active decisions, with *Unban*.
  - *Ban an address* adds a ban, throttle or captcha decision (captcha is served as a 403) for an address or CIDR range, with a duration and reason.
  - *Look up an address* lists every decision for it, community blocklist included, and can delete them all.
  - Caddy picks a change up at the bouncer's next pull (the pull interval, 60 seconds by default).
- **Whitelists**: requests that match a whitelist raise no CrowdSec alert, so no ban. A whitelist lists IP addresses, CIDR ranges, AS numbers, countries, or one CrowdSec expression. IP and CIDR entries also go to the CrowdSec allowlist `ingressi`, which keeps the community blocklist from banning them. Banning a whitelisted address from the dashboard asks for confirmation.
- **Settings**:
  - The master switch, **Apply to all hosts**, the pull interval and the LAPI timeout.
  - The connection to CrowdSec, the bouncer's last pull and the installed collections.
  - Every host with whether it uses the bouncer now.

### Whitelists in CrowdSec

Each whitelist becomes a parser whitelist in `/etc/crowdsec/parsers/s02-enrich/zz-ingressi-<id>.yaml`. The `zz-` prefix puts it after `geoip-enrich`, which sets the AS number and country. The page shows the YAML.

For example, a whitelist of kind *AS numbers* with `131429, 45899, 18403, 45903, 7552, 24086` and reason *Trusted ASN* is written as:

```yaml
name: "ingressi/wl-1"
description: "Ingressi whitelist: Trusted ASNs"
whitelist:
  reason: "Trusted ASN"
  expression:
    - "evt.Meta.ASNNumber in ['131429', '45899', '18403', '45903', '7552', '24086']"
```

You no longer need to write the file, run `crowdsec -t` and restart CrowdSec yourself. Within a few seconds the watcher in the `crowdsec` container (`docker/crowdsec/ingressi-sync.sh`) does all of that:
1. It copies the files in.
2. It runs `crowdsec -t`.
3. If the test passes, it reloads CrowdSec and syncs the allowlist. If the test fails, it puts the previous files back. The page then shows CrowdSec's message.

*Apply again* hands the whitelists over once more.

Do not edit `zz-ingressi-*.yaml` by hand: the next change overwrites them. Whitelists of your own can sit next to them under other names.

## REST API

Under `/api/v1/crowdsec` (see the API reference):

| Endpoint | Purpose |
| --- | --- |
| `status` | Configuration, connection, active decisions, protected hosts |
| `alerts`, `alerts/{id}` | Alerts. Filters: `since`, `ip`, `scenario`, `origin`, `has_active_decision`, `limit` |
| `decisions` | `GET` lists decisions (`?ip=` looks one address up in every list); `POST` `{ value, type, duration, reason, bypassWhitelist }`; `DELETE ?ip=` |
| `decisions/{id}` | `DELETE` one decision |
| `whitelists`, `whitelists/{id}`, `whitelists/apply` | Manage the whitelists |

Other places in the API:
- The global settings are the `crowdsec` group of `/api/v1/settings/{group}`: `enabled`, `apply_to_all_hosts`, `ticker_interval`, `lapi_timeout`.
- A proxy host's setting is its `crowdsec` field: `{ "enabled": true }`, `{ "enabled": false }`, or `null` to inherit.

The CrowdSec endpoints answer `404` with `CROWDSEC_NOT_CONFIGURED` when the overlay is not in use, and `502` with `CROWDSEC_UNAVAILABLE` when the local API cannot be reached.

## Environment variables (web service)

| Variable | Purpose | Default |
| --- | --- | --- |
| `CROWDSEC_BOUNCER_KEY` | The Caddy bouncer's key. Setting it turns the integration on for this instance | None |
| `CROWDSEC_LAPI_URL` | CrowdSec local API | `http://crowdsec:8080` |
| `CROWDSEC_METRICS_URL` | CrowdSec Prometheus endpoint (active decision counts) | None (the overlay sets `http://crowdsec:6060/metrics`) |
| `CROWDSEC_MACHINE_ID` / `CROWDSEC_MACHINE_PASSWORD` | The dashboard's machine account (alerts, decisions) | `ingressi-web` / None |
| `CROWDSEC_MANAGED_DIR` | Directory shared with the `crowdsec` container for whitelists | None (the overlay sets `/crowdsec-managed`) |

## Limits

- **After every configuration apply, there is a short window before the bouncer blocks again.** Each apply re-creates the bouncer in Caddy. It allows requests until its first pull is done, a few seconds including the community blocklist. The WAF and every other protection keep working meanwhile.
- **Captcha decisions are served as a 403.** The bouncer has no captcha page.
- **The overlay serves one web node.** Only `web` gets the CrowdSec settings and the shared volume. In high availability, add them to the other web nodes too, or the whitelists are written only while `web` leads.
- **Instances share settings, not CrowdSec.** Instance sync copies the CrowdSec settings and host modes to slaves. A slave uses the bouncer only if its own environment configures CrowdSec.
