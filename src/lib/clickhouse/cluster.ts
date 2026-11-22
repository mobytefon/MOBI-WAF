import type { ClickHouseClient, ClickHouseSettings } from '@clickhouse/client';

/**
 * Centralised analytics over several ClickHouse servers (documentation/clickhouse-cluster.md).
 *
 * Every node keeps writing its own events into its local MergeTree tables. On
 * the node that sets CLICKHOUSE_CLUSTER (the name of a cluster in ClickHouse's
 * `remote_servers`), start-up also creates a `<db>_cluster` database holding
 * Distributed tables with the same names, and every read query runs with that
 * database as its default, so the existing queries (bare `traffic_events` /
 * `waf_events`) read the whole cluster without being rewritten.
 */

const IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

const CLUSTER_TABLES = ['traffic_events', 'waf_events'] as const;

function parseClusterName(raw: string | undefined): string | null {
  const name = raw?.trim() ?? '';
  if (name === '') return null;
  if (!IDENTIFIER.test(name)) {
    throw new Error(`CLICKHOUSE_CLUSTER contains invalid characters: ${name}`);
  }
  return name;
}

const CH_CLUSTER = parseClusterName(process.env.CLICKHOUSE_CLUSTER);

/** True when this node reads analytics from the whole ClickHouse cluster. */
export function isClusterEnabled(): boolean {
  return CH_CLUSTER !== null;
}

/** The database read queries run against: the Distributed tables' database when the cluster is on. */
export function clusterQueryDatabase(chDb: string): string {
  return CH_CLUSTER ? `${chDb}_cluster` : chDb;
}

/**
 * Settings for read queries over the Distributed tables: an unreachable node
 * leaves its share out instead of failing the page, and `IN (SELECT … FROM
 * <distributed>)` subqueries are evaluated once and sent to every shard.
 */
export function clusterReadSettings(): ClickHouseSettings {
  if (!CH_CLUSTER) return {};
  return { skip_unavailable_shards: 1, distributed_product_mode: 'global' };
}

/**
 * Create (or re-create) the Distributed tables over this node's local tables.
 * Re-created on every start: it only touches metadata, and keeps their columns
 * in step with the local tables after the start-up column migrations.
 */
export async function ensureDistributedTables(ch: ClickHouseClient, chDb: string): Promise<void> {
  if (!CH_CLUSTER) return;
  const clusterDb = clusterQueryDatabase(chDb);
  await ch.command({ query: `CREATE DATABASE IF NOT EXISTS ${clusterDb}` });
  for (const table of CLUSTER_TABLES) {
    await ch.command({
      query:
        `CREATE OR REPLACE TABLE ${clusterDb}.${table} AS ${chDb}.${table} ` +
        `ENGINE = Distributed('${CH_CLUSTER}', '${chDb}', '${table}')`,
    });
  }
}
