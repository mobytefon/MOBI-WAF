/**
 * Argus Sentinel ML (documentation/argus-ml.md): the mlcheck action built
 * into the Caddy image, the socket volume caddy mounts in docker-compose.yml
 * (the l4-port-manager recreates caddy from that file), the sidecar overlay,
 * and the rule sets the guide tells people to paste, which must reach Caddy
 * unchanged. No YAML parser: the compose files are plain block style.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { filterCustomDirectives } from '@/src/lib/caddy-waf';

const ROOT = join(__dirname, '../..');
const read = (file: string) => readFileSync(join(ROOT, file), 'utf8').replace(/\r\n/g, '\n');

/** A top-level service's lines up to the next service, without comments. */
function service(file: string, name: string): string {
  const lines = read(file).split('\n');
  const start = lines.indexOf(`  ${name}:`);
  expect(start, `${file} has service ${name}`).toBeGreaterThanOrEqual(0);
  const body: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^ {0,2}\S/.test(line)) break;
    if (!/^\s*#/.test(line)) body.push(line.replace(/\s+#.*$/, ''));
  }
  return `\n${body.join('\n')}`;
}

/** The fenced code blocks of the guide that hold SecLang directives. */
function ruleBlocks(): string[] {
  const blocks: string[] = [];
  let current: string[] | null = null;
  for (const line of read('documentation/argus-ml.md').split('\n')) {
    if (/^\s*```/.test(line)) {
      if (current) blocks.push(current.join('\n'));
      current = current ? null : [];
    } else if (current) {
      current.push(line.trim());
    }
  }
  return blocks.filter((block) => /^Sec(Rule|Action) /m.test(block));
}

describe('Argus ML integration', () => {
  it('builds the mlcheck action into Caddy', () => {
    expect(read('docker/caddy/go.mod')).toMatch(/\n\tgithub\.com\/mobytefon\/coraza-mlcheck v\d+\.\d+\.\d+\n/);
    expect(read('docker/caddy/tools.go')).toContain('_ "github.com/mobytefon/coraza-mlcheck"');
    expect(read('docker/caddy/build.sh')).toMatch(/\ngithub\.com\/mobytefon\/coraza-mlcheck\n/);
    const dockerfile = read('docker/caddy/Dockerfile');
    expect(dockerfile).toMatch(/mkdir -p [^\n]*\/run\/argus/);
    // Either container may create the volume first; the sidecar has no capability.
    expect(dockerfile).toContain('chmod 1777 /run/argus');
  });

  it('mounts the socket volume in caddy from docker-compose.yml itself', () => {
    expect(service('docker-compose.yml', 'caddy')).toContain('- argus-run:/run/argus');
    expect(read('docker-compose.yml')).toMatch(/\nvolumes:\n(?: {2}.*\n|\s*#.*\n)*? {2}argus-run:\n/);
  });

  it('runs the sidecar without a network, read-only, on the shared volume', () => {
    const overlay = read('docker-compose.argus.yml');
    const sidecar = service('docker-compose.argus.yml', 'argus-sidecar');
    expect(overlay).not.toMatch(/\n {2}caddy:/);
    expect(overlay).not.toContain('docker.sock');
    expect(sidecar).toContain('network_mode: none');
    expect(sidecar).toContain('read_only: true');
    expect(sidecar).toContain('cap_drop: ["ALL"]');
    expect(sidecar).not.toMatch(/\n {4}ports:/);
    expect(sidecar).toContain('- ${ARGUS_MODEL_DIR:?ERROR - ARGUS_MODEL_DIR is required}:/model:ro');
    expect(sidecar).toContain('- argus-run:/run/argus');
    expect(sidecar).toContain('ARGUS_SOCKET: /run/argus/argus.sock');
  });

  it('runs the sidecar as the same user as caddy (0:0, rootless Docker)', () => {
    expect(service('docker-compose.yml', 'caddy')).toContain('user: "0:0"');
    expect(service('docker-compose.argus.yml', 'argus-sidecar')).toContain('user: "${ARGUS_USER:-0:0}"');
    expect(read('docker-compose.argus.yml')).toMatch(/argus-sidecar:\$\{ARGUS_SIDECAR_VERSION:-v0\.2\.1\}/);
  });

  it('keeps the sidecar concurrency default equal to the mlcheck default (16)', () => {
    expect(service('docker-compose.argus.yml', 'argus-sidecar')).toContain(
      'ARGUS_MAX_CONCURRENT_RPCS: ${ARGUS_MAX_CONCURRENT_RPCS:-16}'
    );
  });

  it('documents rule sets that reach Caddy unchanged', () => {
    const blocks = ruleBlocks();
    expect(blocks.length).toBeGreaterThanOrEqual(3);
    const ids = new Set<string>();
    for (const block of blocks) {
      const lines = block.split('\n').filter((line) => line.trim());
      const { kept, dropped } = filterCustomDirectives(block, { crsLoaded: true });
      expect(dropped, block).toEqual([]);
      expect(kept.map((line) => line.trim())).toEqual(lines.map((line) => line.trim()));
      for (const line of lines) {
        const id = /"id:(\d+),phase:2,/.exec(line)?.[1];
        expect(id, line).toBeDefined();
        expect(Number(id)).toBeGreaterThanOrEqual(1899999099);
        expect(Number(id)).toBeLessThanOrEqual(1899999199);
        ids.add(id!);
      }
    }
    // The detect set plus the threshold line, pasted together, is accepted too.
    const [detect, threshold] = blocks;
    expect(filterCustomDirectives(`${threshold}\n${detect}`, { crsLoaded: true }).dropped).toEqual([]);
    expect(ids).toEqual(new Set(['1899999099', '1899999100', '1899999101', '1899999102']));
  });
});
