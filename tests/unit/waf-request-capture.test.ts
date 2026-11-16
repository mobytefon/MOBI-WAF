/**
 * The full request kept with a WAF event (waf-request-capture.ts): the body
 * cleaned (credentials redacted, uploaded files left out) and cut to
 * 32 KiB, and the value each rule matched kept around the match, even when
 * the match lies past the stored body or past what Coraza logs of a value.
 */
import { describe, expect, it, vi } from 'vitest';

vi.mock('@/src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  const db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => db);
});
vi.mock('maxmind', () => ({ default: { open: vi.fn().mockResolvedValue(null) } }));
vi.mock('node:fs', () => ({
  existsSync: vi.fn().mockReturnValue(false),
  statSync: vi.fn().mockReturnValue({ size: 0 }),
  createReadStream: vi.fn(),
}));

import { parseLine } from '@/src/lib/waf-log-parser';
import { locateMatch } from '@/src/lib/waf-match-locate';
import {
  captureAuditRequest,
  MAX_STORED_BODY_BYTES,
  sanitizeRequestBody,
  WAF_CAPTURE_KEY,
  wafRequestViewOf,
  type WafRequestCapture,
} from '@/src/lib/waf-request-capture';

const isCredential = (name: string) => /pass|token|secret/i.test(name);

function auditRecord(options: { body: string; contentType: string; uri?: string; data?: string; headers?: Record<string, string[]> }) {
  const message = options.data
    ? [{
        actionset: '',
        message: '',
        data: null,
        error_message:
          `[client "1.2.3.4"] Coraza: Warning. SQL Injection Attack [file "@owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] ` +
          `[line "1"] [id "942100"] [rev ""] [msg "SQL Injection Attack"] [data ${JSON.stringify(options.data)}] [severity "CRITICAL"] ` +
          `[tag "OWASP_CRS"] [unique_id "tx-1"]`,
      }]
    : [];
  return {
    transaction: {
      id: 'tx-1',
      client_ip: '1.2.3.4',
      unix_timestamp: 1_700_000_000_000_000_000,
      is_interrupted: true,
      request: {
        method: 'POST',
        protocol: 'HTTP/2.0',
        uri: options.uri ?? '/api/items',
        headers: { host: ['app.example.com'], 'content-type': [options.contentType], ...(options.headers ?? {}) },
        body: options.body,
      },
    },
    messages: message,
  };
}

function captureOf(record: Record<string, unknown>): WafRequestCapture {
  return record[WAF_CAPTURE_KEY] as WafRequestCapture;
}

describe('locateMatch', () => {
  it('finds the text as it is, then with case and whitespace folded', () => {
    expect(locateMatch('select USER (', 'USER (')).toEqual({ start: 7, end: 13 });
    expect(locateMatch('select User (', 'user (')).toEqual({ start: 7, end: 13 });
    expect(locateMatch('select User\t\t(', 'user (')).toEqual({ start: 7, end: 14 });
    expect(locateMatch('select User(', 'user (')).toEqual({ start: 7, end: 12 });
    expect(locateMatch('nothing here', 'user (')).toBeNull();
  });
});

describe('sanitizeRequestBody', () => {
  it('redacts credential-named JSON, form and multipart fields', () => {
    expect(JSON.parse(sanitizeRequestBody('{"user":"a","password":"p","nested":{"accessToken":"t"}}', 'application/json', isCredential)))
      .toEqual({ user: 'a', password: '[redacted]', nested: { accessToken: '[redacted]' } });
    expect(sanitizeRequestBody('user=a&password=p%40ss', 'application/x-www-form-urlencoded', isCredential)).toBe('user=a&password=[redacted]');
    const multipart = [
      '--XyZ',
      'Content-Disposition: form-data; name="password"',
      '',
      'hunter2',
      '--XyZ',
      'Content-Disposition: form-data; name="note"',
      '',
      'hello',
      '--XyZ--',
      '',
    ].join('\r\n');
    const out = sanitizeRequestBody(multipart, 'multipart/form-data; boundary=XyZ', isCredential);
    expect(out).not.toContain('hunter2');
    expect(out).toContain('name="password"\r\n\r\n[redacted]\r\n');
    expect(out).toContain('hello');
  });

  it('redacts a JSON body that does not parse by pattern', () => {
    expect(sanitizeRequestBody('{"password": "p", "q": "x"', 'application/json', isCredential)).toBe('{"password": "[redacted]", "q": "x"');
  });

  it('leaves uploaded files out, with their size, and keeps binary data as text', () => {
    const multipart = [
      '--b',
      'Content-Disposition: form-data; name="file"; filename="C7EC.jpg"',
      'Content-Type: image/jpeg',
      '',
      '\ufffd\ufffdJFIF'.repeat(1000),
      '--b--',
      '',
    ].join('\r\n');
    const out = sanitizeRequestBody(multipart, 'multipart/form-data; boundary=b', isCredential);
    expect(out).toContain('filename="C7EC.jpg"');
    // Each U+FFFD stands for one byte the client sent: 1000 × (2 + 4) bytes.
    expect(out).toContain('[5.9 KiB of file data not stored]');
    expect(out).not.toContain('JFIF');
    expect(sanitizeRequestBody('\u0000\u0001binary', 'application/octet-stream', isCredential)).toBe('\u0000\u0001binary');
  });
});

describe('captureAuditRequest', () => {
  it('cuts the stored body and still keeps the value a rule matched past the cut', () => {
    const padding = 'a'.repeat(40_000);
    const value = `${padding} select user ( from dual`;
    const body = JSON.stringify({ Body: { Items: [{ Body: { Value: value } }] }, password: 'p' });
    // Coraza logs only the start of the value.
    const data = `Matched Data: user ( found within ARGS:json.Body.Items.0.Body.Value: ${padding.slice(0, 200)}`;
    const record = auditRecord({ body, contentType: 'application/json', data });
    captureAuditRequest(record, isCredential);

    const request = record.transaction.request;
    expect(Buffer.byteLength(request.body)).toBeLessThanOrEqual(MAX_STORED_BODY_BYTES);
    expect(request.body).not.toContain('"p"');
    const capture = captureOf(record);
    expect(capture.bodyCut).toBe(true);
    expect(capture.bodyBytes).toBe(Buffer.byteLength(body));
    const matched = capture.matchedValues[0];
    expect(matched).toMatchObject({ ruleId: 942100, variable: 'ARGS:json.Body.Items.0.Body.Value', length: value.length });
    expect(matched.offset).toBeGreaterThan(0);
    expect(matched.value.slice(matched.start, matched.end)).toBe('user (');
  });

  it('keeps form, query and header values, never credential ones', () => {
    const record = auditRecord({
      body: 'q=1+union+select&password=x',
      contentType: 'application/x-www-form-urlencoded',
      data: 'Matched Data: union select found within ARGS_POST:q: 1 union select',
    });
    captureAuditRequest(record, isCredential);
    expect(captureOf(record).matchedValues[0]).toMatchObject({ value: '1 union select', start: 2, end: 14 });

    const credential = auditRecord({
      body: 'password=or+1%3D1',
      contentType: 'application/x-www-form-urlencoded',
      data: 'Matched Data: or 1=1 found within ARGS_POST:password: or 1=1',
    });
    captureAuditRequest(credential, isCredential);
    expect(captureOf(credential).matchedValues).toEqual([]);
  });

  it('keeps a binary body as text, flagged, with the match in it', () => {
    // A binary RPC body (NUL bytes) carrying an HTTP request line deep inside.
    const before = '\u0000\u0001'.repeat(5_000);
    const body = `${before}POST /ws/MPL\u0000\u0000\u0000\u0000us/update_stock_isdn_plus HTTP/1.1${'\u0000x'.repeat(5_000)}`;
    const found = 'post /ws/mpl\u0000\u0000\u0000\u0000us/update_stock_isdn_plus http/1';
    const record = auditRecord({
      body,
      contentType: 'application/octet-stream',
      data: `Matched Data: ${found} found within REQUEST_BODY: ${before.slice(0, 100)}`,
    });
    captureAuditRequest(record, isCredential);

    expect(record.transaction.request.body).toBe(body);
    const capture = captureOf(record);
    expect(capture).toMatchObject({ bodyBinary: true, bodyCut: false });
    const matched = capture.matchedValues[0];
    expect(matched).toMatchObject({ variable: 'REQUEST_BODY', length: body.length, offset: before.length - 1024 });
    expect(matched.value.slice(matched.start, matched.end)).toBe('POST /ws/MPL\u0000\u0000\u0000\u0000us/update_stock_isdn_plus HTTP/1');
    expect(wafRequestViewOf(JSON.stringify(record))?.capture?.bodyBinary).toBe(true);
  });

  it('keeps a match in an uploaded file, and nothing when a left-out body does not hold it', () => {
    const multipart = ['--b', 'Content-Disposition: form-data; name="file"; filename="x.php"', '', `${'z'.repeat(9_000)}<?php system($_GET[c]); ?>`, '--b--', ''].join('\r\n');
    const file = auditRecord({
      body: multipart,
      contentType: 'multipart/form-data; boundary=b',
      data: 'Matched Data: <?php found within REQUEST_BODY: --b',
    });
    captureAuditRequest(file, isCredential);
    const matched = captureOf(file).matchedValues[0];
    expect(matched.value.slice(matched.start, matched.end)).toBe('<?php');
    expect(matched.value.length).toBeLessThanOrEqual(768);

    const missing = auditRecord({
      body: ['--b', 'Content-Disposition: form-data; name="file"; filename="a.bin"', '', 'data', '--b--', ''].join('\r\n'),
      contentType: 'multipart/form-data; boundary=b',
      data: 'Matched Data: transformed found within REQUEST_BODY: --b',
    });
    captureAuditRequest(missing, isCredential);
    expect(captureOf(missing).matchedValues).toEqual([]);
  });

  it('leaves a record without body or matched value as it is', () => {
    const record = auditRecord({ body: '', contentType: 'text/plain' }) as Record<string, unknown>;
    captureAuditRequest(record, isCredential);
    expect(record[WAF_CAPTURE_KEY]).toBeUndefined();
  });
});

describe('parseLine with a request body', () => {
  it('stores the cleaned body and the matched values in raw_data', () => {
    const record = auditRecord({
      body: '{"name":"x","password":"secret-1"}',
      contentType: 'application/json',
      data: 'Matched Data: x found within ARGS:json.name: x',
    });
    const row = parseLine(JSON.stringify(record), new Map());
    expect(row).not.toBeNull();
    expect(row!.raw_data).not.toContain('secret-1');
    const view = wafRequestViewOf(row!.raw_data);
    expect(view?.requestLine).toBe('POST /api/items HTTP/2.0');
    expect(view?.headers[0]).toEqual(['host', 'app.example.com']);
    expect(view?.body).toContain('"password":"[redacted]"');
    expect(view?.capture?.matchedValues).toEqual([
      { ruleId: 942100, variable: 'ARGS:json.name', value: 'x', offset: 0, length: 1, start: 0, end: 1 },
    ]);
  });
});

describe('wafRequestViewOf', () => {
  it('reads records stored before bodies were kept', () => {
    const view = wafRequestViewOf(JSON.stringify(auditRecord({ body: '', contentType: 'text/plain', headers: { 'content-length': ['12'] } })));
    expect(view).toMatchObject({ body: '', contentLength: 12, capture: null });
    expect(wafRequestViewOf('not json')).toBeNull();
  });

  it('drops a malformed capture', () => {
    const record = { ...auditRecord({ body: 'x', contentType: 'text/plain' }), [WAF_CAPTURE_KEY]: { bodyBytes: 'many' } };
    expect(wafRequestViewOf(JSON.stringify(record))?.capture).toBeNull();
  });
});
