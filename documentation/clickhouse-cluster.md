# Centralised analytics (several nodes)

When the proxy runs on several nodes, each node's web container parses that node's own Caddy and WAF logs into that node's own ClickHouse. With centralised analytics, one node (the central node, usually the [instance sync](instance-sync.md) master) shows the traffic and WAF events of every node: on the Analytics, Security events and WAF pages, in alerts, reports and the AI analyst.

Nothing is copied between nodes. The central node's ClickHouse holds a `<CLICKHOUSE_DB>_cluster` database (`analytics_cluster` by default) with [Distributed](https://clickhouse.com/docs/engines/table-engines/special/distributed) tables `traffic_events` and `waf_events`. They read the local tables of every node at query time, and the central node's dashboard reads through them. Each node keeps writing to, and expiring (`CLICKHOUSE_RETENTION_DAYS`), its own tables as before. No ClickHouse Keeper or ZooKeeper is needed.

The other nodes' dashboards still show their own events only.

For building and shipping the images, `.env`, the access log and the firewall, see [Production deployment](production-deployment.md).

## Requirements

- The same `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` and `CLICKHOUSE_DB` on every node, and preferably the same `CLICKHOUSE_RETENTION_DAYS`.
- The same Ingressi version on every node, so the tables have the same columns.
- The same ClickHouse version on every node: set `CLICKHOUSE_IMAGE` (read by both overlays) to the same pinned tag everywhere, e.g. `CLICKHOUSE_IMAGE=clickhouse/clickhouse-server:26.10.4-alpine`, rather than the default `latest-alpine`.
- A private network between the nodes: the central node reaches the other nodes' ClickHouse native port, TCP 9000, unencrypted.

## Setting it up (three nodes)

Example addresses: node 1 (central) `10.0.0.11`, node 2 `10.0.0.12`, node 3 `10.0.0.13`.

**Nodes 2 and 3.** In `.env`, add this node's private address and the shard overlay:

```env
COMPOSE_FILE=docker-compose.yml:docker-compose.clickhouse-shard.yml
CLICKHOUSE_SHARD_BIND=10.0.0.12
```

`docker compose up -d` then publishes ClickHouse's native port on that address only. Allow only the central node to reach it, for example:

```bash
ufw allow from 10.0.0.11 to any port 9000 proto tcp
```

With rootless Docker the published ports are ordinary sockets of the `rootlesskit` process, so ufw rules apply to them as to any other service. With rootful Docker they bypass ufw: filter in the `DOCKER-USER` iptables chain instead. [Production deployment](production-deployment.md#firewall) has a complete rule set.

The nodes can start in any order: the central node creates its Distributed tables without reaching the other nodes, and leaves out a node that does not answer yet.

**Node 1 (central).** In `.env`:

```env
COMPOSE_FILE=docker-compose.yml:docker-compose.clickhouse-central.yml
CH_SHARD2_HOST=10.0.0.12
CH_SHARD3_HOST=10.0.0.13
```

`docker compose up -d` mounts `docker/clickhouse/cluster/remote-servers.xml` (the cluster `waf_cluster`: this server plus the two hosts above, credentials from the container's environment) and sets `CLICKHOUSE_CLUSTER=waf_cluster` for the web container. At start-up the web container creates the Distributed tables, and re-creates them at every start so they follow the local tables' columns after an upgrade.

For a different number of nodes, add or remove `<shard>` blocks in `remote-servers.xml` and the matching `CH_SHARD<N>_HOST` lines in `docker-compose.clickhouse-central.yml`.

Other overlays can be listed in `COMPOSE_FILE` too, separated by `:`.

## Checking it

On the central node:

```bash
docker exec -it ingressi-clickhouse clickhouse-client --user ingressi --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT _shard_num, count() FROM analytics_cluster.traffic_events GROUP BY _shard_num ORDER BY _shard_num"
```

shows one row per node that has events.

## When a node is down

Queries skip the shards they cannot reach (`skip_unavailable_shards`): the pages still load, with the figures of the nodes that answered. Nothing says that a node is missing, so watch the nodes themselves.

## Turning it off

Remove `docker-compose.clickhouse-central.yml` from `COMPOSE_FILE` on the central node and recreate the stack: the dashboard goes back to that node's own events. The `analytics_cluster` database is left in place; drop it with `DROP DATABASE analytics_cluster` if you like (the local tables are not touched).
