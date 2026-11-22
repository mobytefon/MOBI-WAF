import { afterEach, describe, expect, it, vi } from 'vitest';

// Centralised analytics (src/lib/clickhouse/cluster.ts): reads go through the
// Distributed tables of `<db>_cluster`, writes stay on this node's tables.

type CreateOptions = { database?: string; clickhouse_settings?: Record<string, unknown> };

function mockClickHouse() {
  const commands: string[] = [];
  const clients: { options: CreateOptions; query: ReturnType<typeof vi.fn>; insert: ReturnType<typeof vi.fn> }[] = [];
  const createClient = vi.fn((options: CreateOptions) => {
    const query = vi.fn(async () => ({ json: async () => [{ create_table_query: 'TTL ts + toIntervalDay(30)', value: '7' }] }));
    const insert = vi.fn(async () => {});
    const command = vi.fn(async ({ query: q }: { query: string }) => { commands.push(q); });
    clients.push({ options, query, insert });
    return { query, command, insert, close: vi.fn(async () => {}) };
  });
  vi.doMock('@clickhouse/client', () => ({ createClient }));
  return { commands, clients, createClient };
}

describe('clickhouse cluster mode', () => {
  afterEach(() => {
    vi.resetModules();
    vi.unstubAllEnvs();
    vi.doUnmock('@clickhouse/client');
  });

  it('without CLICKHOUSE_CLUSTER, reads and writes share one client on the local database', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');
    vi.stubEnv('CLICKHOUSE_CLUSTER', '');
    const { commands, clients, createClient } = mockClickHouse();

    const { initClickHouse, insertWafEvents, queryWafCount } = await import('@/src/lib/clickhouse/client');
    await initClickHouse();
    await insertWafEvents([{ ts: 0, host: 'a', client_ip: '1.1.1.1', country_code: null, rule_id: 1, rule_message: null, severity: null, raw_data: null, blocked: true, method: 'GET', uri: '/' }]);
    await expect(queryWafCount(0, 60)).resolves.toBe(7);

    expect(createClient).toHaveBeenCalledTimes(1);
    expect(clients[0].options.database).toBe('analytics');
    expect(commands.some((q) => q.includes('Distributed'))).toBe(false);
    expect(commands.some((q) => q.includes('_cluster'))).toBe(false);
  });

  it('with CLICKHOUSE_CLUSTER, creates Distributed tables and reads through them', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');
    vi.stubEnv('CLICKHOUSE_CLUSTER', 'waf_cluster');
    const { commands, clients } = mockClickHouse();

    const { initClickHouse, insertTrafficEvents, queryWafCount, getClient } = await import('@/src/lib/clickhouse/client');
    await initClickHouse();

    expect(commands).toContain('CREATE DATABASE IF NOT EXISTS analytics_cluster');
    expect(commands).toContain(
      "CREATE OR REPLACE TABLE analytics_cluster.traffic_events AS analytics.traffic_events ENGINE = Distributed('waf_cluster', 'analytics', 'traffic_events')",
    );
    expect(commands).toContain(
      "CREATE OR REPLACE TABLE analytics_cluster.waf_events AS analytics.waf_events ENGINE = Distributed('waf_cluster', 'analytics', 'waf_events')",
    );
    // The Distributed tables are created after the local tables they copy.
    expect(commands.indexOf('CREATE DATABASE IF NOT EXISTS analytics_cluster'))
      .toBeGreaterThan(commands.findIndex((q) => q.includes('CREATE TABLE IF NOT EXISTS waf_events')));

    await insertTrafficEvents([{ ts: 0, client_ip: '1.1.1.1', country_code: null, host: 'a', method: 'GET', uri: '/', status: 200, proto: 'HTTP/1.1', bytes_sent: 1, user_agent: '', is_blocked: false }]);
    await expect(queryWafCount(0, 60)).resolves.toBe(7);
    getClient();

    const write = clients.find((c) => c.options.database === 'analytics');
    const read = clients.find((c) => c.options.database === 'analytics_cluster');
    expect(clients).toHaveLength(2);
    expect(write?.insert).toHaveBeenCalledTimes(1);
    expect(write?.options.clickhouse_settings).toEqual({ async_insert: 1, wait_for_async_insert: 0 });
    expect(read?.insert).not.toHaveBeenCalled();
    expect(read?.query).toHaveBeenCalledTimes(1);
    expect(read?.options.clickhouse_settings).toEqual({ skip_unavailable_shards: 1, distributed_product_mode: 'global' });
  });

  it('rejects a cluster name that is not an identifier', async () => {
    vi.stubEnv('CLICKHOUSE_PASSWORD', 'test-clickhouse-password');
    vi.stubEnv('CLICKHOUSE_CLUSTER', "waf'); DROP TABLE x; --");
    mockClickHouse();

    await expect(import('@/src/lib/clickhouse/client')).rejects.toThrow(/CLICKHOUSE_CLUSTER/);
  });
});
