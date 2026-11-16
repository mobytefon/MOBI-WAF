/**
 * docker-compose.crowdsec.yml: CrowdSec (docker/crowdsec) with its own
 * PostgreSQL on an internal network, reading Caddy's access log read-only,
 * and the web service pointed at its local API. The dashboard applies
 * whitelists through a shared volume and a watcher in the crowdsec
 * container, never through the Docker socket, and the caddy service is left
 * alone (the l4-port-manager recreates it with at most one extra file).
 * `docker compose … config` validates the file itself; this pins what the
 * dashboard and the watcher depend on. No YAML parser: the files are plain
 * block style, as in compose-postgres.test.ts.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(__dirname, '../..');
const read = (file: string) => readFileSync(join(ROOT, file), 'utf8').replace(/\r\n/g, '\n');

/** The top-level `section:` of a compose file, its entries and their lines without comments. */
function entries(file: string, section: string): Map<string, string> {
  const lines = read(file).split('\n');
  const start = lines.indexOf(`${section}:`);
  expect(start, `${file} has ${section}:`).toBeGreaterThanOrEqual(0);
  const out = new Map<string, string[]>();
  let current: string | null = null;
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    const name = /^ {2}([a-z0-9-]+):\s*$/.exec(line)?.[1];
    if (name) {
      current = name;
      out.set(name, []);
    } else if (current && !/^\s*#/.test(line)) {
      out.get(current)!.push(line.replace(/\s+#.*$/, ''));
    }
  }
  return new Map([...out].map(([name, body]) => [name, `\n${body.join('\n')}`]));
}

/** The `- item` lines of a service's `key:` list. */
function list(service: string, key: string): string[] {
  const block = new RegExp(`\\n {4}${key}:\\n((?: {6}- .*\\n?)+)`).exec(service)?.[1] ?? '';
  return block.split('\n').map((line) => line.replace(/^ {6}- /, '').trim()).filter(Boolean);
}

const FILE = 'docker-compose.crowdsec.yml';
const services = entries(FILE, 'services');
const crowdsec = services.get('crowdsec')!;
const db = services.get('crowdsec-db')!;
const web = services.get('web')!;
const required = (name: string) => `\${${name}:?ERROR - ${name} is required}`;

describe('docker-compose.crowdsec.yml', () => {
  it('adds crowdsec and its database, extends web, and leaves caddy and the L4 sidecar alone', () => {
    expect([...services.keys()].sort()).toEqual(['crowdsec', 'crowdsec-db', 'web']);
    expect(crowdsec).toContain('container_name: ingressi-crowdsec');
    expect(db).toContain('container_name: ingressi-crowdsec-db');
    expect(crowdsec).toMatch(/\n {4}build:\n {6}context: \.\n {6}dockerfile: docker\/crowdsec\/Dockerfile/);
  });

  it('mounts no Docker socket and publishes no port', () => {
    const overlay = read(FILE);
    expect(overlay).not.toContain('docker.sock');
    expect(overlay).not.toMatch(/DOCKER_HOST/);
    for (const [name, body] of services) {
      expect(body, name).not.toMatch(/\n {4}(ports|privileged|security_opt):/);
    }
  });

  it('requires every secret, the same one wherever it is used', () => {
    expect(crowdsec).toContain(`BOUNCER_KEY_ingressi_caddy: ${required('CROWDSEC_BOUNCER_KEY')}`);
    expect(crowdsec).toContain(`CROWDSEC_DB_PASSWORD: ${required('CROWDSEC_DB_PASSWORD')}`);
    expect(crowdsec).toContain(`CROWDSEC_MACHINE_PASSWORD: ${required('CROWDSEC_MACHINE_PASSWORD')}`);
    expect(crowdsec).toContain('ENROLL_KEY: ${CROWDSEC_ENROLL_KEY:-}');
    expect(db).toContain(`POSTGRES_PASSWORD: ${required('CROWDSEC_DB_PASSWORD')}`);
    expect(web).toContain(`CROWDSEC_BOUNCER_KEY: ${required('CROWDSEC_BOUNCER_KEY')}`);
    expect(web).toContain(`CROWDSEC_MACHINE_PASSWORD: ${required('CROWDSEC_MACHINE_PASSWORD')}`);
    // The web service never sees the database password.
    expect(web).not.toContain('CROWDSEC_DB_PASSWORD');

    const env = read('.env.example');
    for (const name of ['CROWDSEC_BOUNCER_KEY', 'CROWDSEC_MACHINE_PASSWORD', 'CROWDSEC_DB_PASSWORD']) {
      expect(env).toMatch(new RegExp(`\\n# ${name}=\\n`));
    }
    expect(env).toMatch(/# CROWDSEC \(OPTIONAL\)[\s\S]*openssl rand -hex 32[\s\S]*# CROWDSEC_BOUNCER_KEY=/);
  });

  it('installs the Caddy collections and registers the bouncer and the dashboard machine', () => {
    expect(crowdsec).toContain(
      'COLLECTIONS: crowdsecurity/caddy crowdsecurity/base-http-scenarios crowdsecurity/http-cve crowdsecurity/whitelist-good-actors'
    );
    expect(crowdsec).toContain('PARSERS: crowdsecurity/geoip-enrich');
    expect(crowdsec).toContain('CROWDSEC_MACHINE_ID: ingressi-web');
    expect(web).toContain('CROWDSEC_MACHINE_ID: ingressi-web');
    expect(crowdsec).toContain('init: true');
    expect(crowdsec).toMatch(/\n {6}test: \["CMD", "cscli", "lapi", "status"\]/);
    expect(crowdsec).toMatch(/\n {6}crowdsec-db:\n {8}condition: service_healthy/);
  });

  it("reads Caddy's logs read-only and shares only the managed volume with web", () => {
    expect(list(crowdsec, 'volumes')).toEqual([
      '${CADDY_LOGS_DIR:-caddy-logs}:/var/log/caddy:ro',
      'crowdsec-config:/etc/crowdsec',
      'crowdsec-data:/var/lib/crowdsec/data',
      'crowdsec-managed:/ingressi',
    ]);
    expect(list(web, 'volumes')).toEqual(['crowdsec-managed:/crowdsec-managed']);
    expect(web).toContain('CROWDSEC_MANAGED_DIR: /crowdsec-managed');
    expect([...entries(FILE, 'volumes').keys()]).toEqual([
      'crowdsec-config',
      'crowdsec-data',
      'crowdsec-managed',
      'crowdsec-db-data',
    ]);
    // The base stack writes the logs where crowdsec reads them.
    expect(entries('docker-compose.yml', 'services').get('caddy')).toContain('- ${CADDY_LOGS_DIR:-caddy-logs}:/logs');
  });

  it('keeps the database on an internal network that only crowdsec joins', () => {
    expect(db).toContain('\n    image: postgres:17-alpine');
    expect(db).toContain('pg_isready -U crowdsec -d crowdsec');
    expect(list(db, 'volumes')).toEqual(['crowdsec-db-data:/var/lib/postgresql/data']);
    expect(list(db, 'networks')).toEqual(['crowdsec-internal']);
    expect(list(crowdsec, 'networks')).toEqual(['caddy-network', 'crowdsec-internal']);
    expect(web).not.toMatch(/\n {4}networks:/);
    expect(entries(FILE, 'networks').get('crowdsec-internal')).toContain('internal: true');
  });

  it('points web at the local API and metrics on the compose network', () => {
    expect(web).toContain('CROWDSEC_LAPI_URL: http://crowdsec:8080');
    expect(web).toContain('CROWDSEC_METRICS_URL: http://crowdsec:6060/metrics');
    const config = read('docker/crowdsec/config.yaml.local');
    expect(config).toContain('listen_uri: 0.0.0.0:8080');
    expect(config).toMatch(/listen_addr: 0\.0\.0\.0\n {2}listen_port: 6060/);
  });
});

describe('docker/crowdsec image', () => {
  const dockerfile = read('docker/crowdsec/Dockerfile');
  const config = read('docker/crowdsec/config.yaml.local');
  const acquis = read('docker/crowdsec/acquis.yaml');
  const entrypoint = read('docker/crowdsec/ingressi-entrypoint.sh');
  const sync = read('docker/crowdsec/ingressi-sync.sh');

  it('builds on a pinned CrowdSec image with jq and its own entrypoint', () => {
    const from = dockerfile.split('\n').filter((line) => line.startsWith('FROM '));
    expect(from).toHaveLength(1);
    expect(from[0]).toMatch(/^FROM crowdsecurity\/crowdsec:v\d+\.\d+\.\d+@sha256:[a-f0-9]{64}$/);
    expect(dockerfile).toContain('apk add --no-cache jq');
    expect(dockerfile).toContain('ENTRYPOINT ["/bin/bash", "/usr/local/bin/ingressi-entrypoint.sh"]');
  });

  it('stores decisions in crowdsec-db, with the password from the environment only', () => {
    expect(config).toMatch(/db_config:\n {2}type: postgresql\n/);
    expect(config).toContain('  host: crowdsec-db\n');
    // CrowdSec expands every ${VAR} in the file, comments included.
    expect(config.match(/\$\{[^}]*\}/g)).toEqual(['${CROWDSEC_DB_PASSWORD}']);
  });

  it('reads only the JSON access log, as Caddy logs', () => {
    expect(acquis).toMatch(/filenames:\n {2}- \/var\/log\/caddy\/access\.log\nlabels:\n {2}type: caddy\n/);
    expect(acquis).not.toMatch(/^\s*-.*waf/m);
  });

  it('registers the machine once the local API is up, then hands over to docker_start.sh', () => {
    expect(entrypoint).toContain('lapi status');
    expect(entrypoint).toMatch(/machines add "\$machine" \\\n\s+--password "\$CROWDSEC_MACHINE_PASSWORD" -f \/dev\/null --force/);
    expect(entrypoint).toContain('exec /usr/local/bin/ingressi-sync.sh');
    expect(entrypoint).toMatch(/\nbootstrap &\n/);
    expect(entrypoint.trimEnd().split('\n').at(-1)).toBe('exec /bin/bash /docker_start.sh "$@"');
  });

  it('applies the contract the dashboard writes, and never touches the Docker socket', () => {
    for (const path of [
      'desired="$root/desired"',
      'status="$root/status"',
      '"$desired/generation"',
      '"$desired/whitelists"',
      '"$desired/allowlist.txt"',
      '"$desired/collections.txt"',
      '"$status/result.json"',
      '"$status/snapshot.json"',
    ]) {
      expect(sync).toContain(path);
    }
    expect(sync).toContain("whitelist_re='^zz-ingressi-[A-Za-z0-9_-]+\\.yaml$'");
    expect(sync).toContain('parser_dir="${INGRESSI_PARSER_DIR:-/etc/crowdsec/parsers/s02-enrich}"');
    expect(sync).toContain("'{generation: $generation, ok: $ok, message: $message, at: $at}'");
    expect(sync).toContain('crowdsec -c "$config_file" -t');
    expect(sync).toContain('kill -HUP');
    for (const command of ['allowlists create', 'allowlists add', 'allowlists remove', 'allowlists inspect']) {
      expect(sync).toContain(command);
    }
    expect(sync).toContain('poll_interval="${INGRESSI_SYNC_INTERVAL:-5}"');
    expect(sync).toContain('snapshot_interval="${INGRESSI_SNAPSHOT_INTERVAL:-60}"');
    expect(sync).not.toMatch(/docker\.sock|\bdocker /);
  });
});
