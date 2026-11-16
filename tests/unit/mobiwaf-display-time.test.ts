/**
 * MOBI-WAF: times shown in Vietnam time (UTC+7), analytics buckets aligned
 * to it, and the CrowdSec subpages kept out of the sidebar.
 */
import { describe, expect, it } from 'vitest';
import { fromZonedInputValue, toZonedInputValue, zoned } from '@/src/lib/display-time';
import { resolveRange } from '@/src/lib/analytics/range';
import { formatWhen } from '@/app/(dashboard)/crowdsec/format';
import { NAV_GROUPS, NAV_PAGES } from '@/src/lib/navigation';

const AT = Date.UTC(2026, 9, 3, 18, 30, 5); // 3 Oct 2026 18:30:05 UTC = 4 Oct 01:30:05 UTC+7

describe('display time (UTC+7)', () => {
  it('reads Vietnam wall-clock time through getUTC*', () => {
    const d = zoned(AT);
    expect([d.getUTCDate(), d.getUTCHours(), d.getUTCMinutes()]).toEqual([4, 1, 30]);
    expect(Number.isNaN(zoned('not a date').getTime())).toBe(true);
  });

  it('round-trips datetime-local values as Vietnam time', () => {
    expect(toZonedInputValue(AT / 1000)).toBe('2026-10-04T01:30');
    expect(fromZonedInputValue('2026-10-04T01:30')).toBe(Math.floor(AT / 1000) - 5);
    expect(fromZonedInputValue('2026-10-04')).toBeNull();
  });

  it('labels CrowdSec times UTC+7', () => {
    expect(formatWhen('2026-10-03T18:30:05Z')).toBe('4 Oct 2026, 01:30:05 UTC+7');
  });

  it('starts day buckets at midnight in Vietnam', () => {
    const r = resolveRange({ range: '30d' }, Math.floor(AT / 1000));
    expect((r.start + 7 * 3600) % 86_400).toBe(0);
    expect(r.end - 86_400).toBeLessThanOrEqual(Math.floor(AT / 1000));
    expect(r.end).toBeGreaterThan(Math.floor(AT / 1000));
  });
});

describe('CrowdSec in the sidebar', () => {
  it('lists only the CrowdSec dashboard; its subpages stay in the command palette', () => {
    const security = NAV_GROUPS.flatMap((g) => g.entries).find((e) => e.key === 'security')!;
    const shown = security.pages.filter((p) => !p.hideInSidebar).map((p) => p.href);
    expect(shown.filter((href) => href.startsWith('/crowdsec'))).toEqual(['/crowdsec']);
    expect(NAV_PAGES.map((p) => p.href)).toEqual(expect.arrayContaining(['/crowdsec/alerts', '/crowdsec/decisions', '/crowdsec/whitelists', '/crowdsec/settings']));
  });
});
