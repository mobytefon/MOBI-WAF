/**
 * Server-side render of a WAF event's Full HTTP request and of "Show the
 * value": the request as it went over the wire, and the matched text marked
 * in the value, from the excerpt kept at ingest or from the rule's logdata.
 */
import { describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

vi.mock('@/app/(dashboard)/security/request-actions', () => ({ wafRequestAction: vi.fn() }));

import { FullHttpRequest, MatchedValue } from '@/app/(dashboard)/security/WafRequestDetail';
import { bodyNote, fullRequestText, shownValue } from '@/app/(dashboard)/security/request-view';
import type { WafRequestView } from '@/src/lib/waf-request-capture';

const view: WafRequestView = {
  requestLine: 'POST /msale-service/api/file-attachments?flagRotate=true HTTP/2.0',
  headers: [
    ['host', 'msalepro.example.com'],
    ['content-type', 'multipart/form-data; boundary=b'],
    ['content-length', '1079679'],
  ],
  body: '--b\r\nContent-Disposition: form-data; name="file"; filename="a.jpg"\r\n\r\n[1.0 MiB of file data not stored]\r\n--b--\r\n',
  contentLength: 1_079_679,
  capture: { bodyBytes: 1_079_679, bodyStoredBytes: 120, bodyCut: false, matchedValues: [] },
};

describe('Full HTTP request', () => {
  it('shows the request line, every header, then the body', () => {
    expect(fullRequestText(view).split('\n').slice(0, 5)).toEqual([
      'POST /msale-service/api/file-attachments?flagRotate=true HTTP/2.0',
      'host: msalepro.example.com',
      'content-type: multipart/form-data; boundary=b',
      'content-length: 1079679',
      '',
    ]);
    const html = renderToStaticMarkup(createElement(FullHttpRequest, { state: { status: 'ready', view } }));
    expect(html).toContain('Full HTTP request');
    expect(html).toContain('filename=&quot;a.jpg&quot;');
    expect(html).toContain('[1.0 MiB of file data not stored]');
    expect(html).not.toContain('\\r');
  });

  it('says when the body was cut or not logged', () => {
    expect(bodyNote({ ...view, capture: { bodyBytes: 90_000, bodyStoredBytes: 32_768, bodyCut: true, matchedValues: [] } }))
      .toBe('Only the first 32 KiB of the body is kept (it was 88 KiB).');
    expect(bodyNote({ ...view, body: '', capture: null })).toMatch(/1\.0 MiB body that is not stored/);
    expect(bodyNote(view)).toBeNull();
  });
});

describe('Show the value', () => {
  const variable = 'ARGS:json.Body.Items.0.Body.Value';
  const logged = 'a'.repeat(200);
  const matchedData = `Matched Data: user ( found within ${variable}: ${logged}`;

  it('marks the match in the excerpt kept at ingest, past the logged value', () => {
    const shown = shownValue({
      ruleId: 942100,
      variable,
      found: 'user (',
      logged,
      matchedData,
      captured: [{ ruleId: 942100, variable, value: 'aaaa select user ( from dual', offset: 39_000, length: 39_028, start: 12, end: 18 }],
    });
    expect(shown).toMatchObject({ start: 12, end: 18, cutBefore: true, cutAfter: false, note: null });
    const html = renderToStaticMarkup(createElement(MatchedValue, { shown: shown! }));
    expect(html).toContain('<mark');
    expect(html).toMatch(/<mark[^>]*>user \(<\/mark>/);
  });

  it('says the logged value was cut when the match is not in it', () => {
    const shown = shownValue({ ruleId: 942100, variable, found: 'user (', logged, matchedData, captured: null });
    expect(shown).toMatchObject({ start: -1, cutAfter: true });
    expect(shown?.note).toMatch(/only the start of the value/);
  });

  it('marks the match in the logged value, case folded', () => {
    const shown = shownValue({
      ruleId: 942100,
      variable: 'ARGS:q',
      found: 'union select',
      logged: '1 UNION SELECT 2',
      matchedData: 'Matched Data: union select found within ARGS:q: 1 UNION SELECT 2',
    });
    expect(shown).toMatchObject({ start: 2, end: 14, note: null });
  });

  it('explains the token fingerprint of a libinjection rule', () => {
    const shown = shownValue({
      ruleId: 942100,
      variable: 'ARGS:q',
      found: 'sUEnk',
      logged: "1' union select 1--",
      matchedData: "Matched Data: sUEnk found within ARGS:q: 1' union select 1--",
      message: 'SQL Injection Attack Detected via libinjection',
    });
    expect(shown).toMatchObject({ start: -1 });
    expect(shown?.note).toMatch(/token fingerprint/);
  });

  it('has nothing more to show when the value is the matched text', () => {
    expect(shownValue({ ruleId: 1, variable: 'ARGS:q', found: 'x', logged: 'x', matchedData: 'Matched Data: x found within ARGS:q: x' })).toBeNull();
  });
});
