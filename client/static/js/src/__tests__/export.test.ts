/**
 * Unit Tests -- per-row exportBackup
 *
 * The protected export GET authenticates with the session cookie, so the
 * per-row button refreshes the session and starts a native download through
 * a hidden same-origin anchor: no export token, no URL credential, and no
 * top-level navigation.
 */

import './setup';
import { describe, test, expect, beforeEach, beforeAll, afterAll } from 'bun:test';

interface FakeAnchor {
  tagName: string;
  href: string;
  download: string;
  rel: string;
  style: { display: string };
  clicked: number;
  removed: boolean;
  click(): void;
  remove(): void;
}

const createdAnchors: FakeAnchor[] = [];
let cookieValue = '__Host-arkfile-csrf=csrf-test';
let navigatedTo = '';

const fakeDocument = {
  get cookie() {
    return cookieValue;
  },
  createElement(tag: string): FakeAnchor {
    if (tag !== 'a') throw new Error(`only <a> expected, got <${tag}>`);
    const anchor: FakeAnchor = {
      tagName: 'A',
      href: '',
      download: '',
      rel: '',
      style: { display: '' },
      clicked: 0,
      removed: false,
      click() {
        this.clicked += 1;
      },
      remove() {
        this.removed = true;
      },
    };
    createdAnchors.push(anchor);
    return anchor;
  },
  body: {
    appendChild(_node: unknown) {
      return _node;
    },
  },
};

let lastAlert = '';
let fetchCalls: { url: string; options: any }[] = [];
let refreshOk = true;

const g = globalThis as any;
const saved = {
  document: g.document,
  alert: g.alert,
  fetch: g.fetch,
  location: Object.getOwnPropertyDescriptor(g.window, 'location'),
};

import { exportBackup, exportUrl, EXPORT_DOWNLOAD_PACING_MS } from '../files/export';

describe('exportBackup', () => {
  beforeAll(() => {
    g.document = fakeDocument;
    g.alert = (msg: string) => {
      lastAlert = msg;
    };
    g.fetch = async (url: string, options?: any) => {
      fetchCalls.push({ url, options });
      return { ok: refreshOk, status: refreshOk ? 200 : 401, json: async () => ({}) };
    };
    Object.defineProperty(g.window, 'location', {
      value: {
        get href() {
          return navigatedTo;
        },
        set href(v: string) {
          navigatedTo = v;
        },
      },
      configurable: true,
    });
  });

  afterAll(() => {
    if (saved.document === undefined) delete g.document;
    else g.document = saved.document;
    g.alert = saved.alert;
    g.fetch = saved.fetch;
    if (saved.location) Object.defineProperty(g.window, 'location', saved.location);
    else delete g.window.location;
  });

  beforeEach(() => {
    createdAnchors.length = 0;
    fetchCalls = [];
    lastAlert = '';
    navigatedTo = '';
    refreshOk = true;
    cookieValue = '__Host-arkfile-csrf=csrf-test';
  });

  test('starts a native download through a hidden anchor with no token', async () => {
    await exportBackup('file-id-123');

    expect(createdAnchors.length).toBe(1);
    const anchor = createdAnchors[0]!;
    expect(anchor.href).toBe('/api/files/file-id-123/export');
    expect(anchor.href).not.toContain('token');
    expect(anchor.download).toBe('file-id-123.arkbackup');
    expect(anchor.style.display).toBe('none');
    expect(anchor.clicked).toBe(1);
    expect(anchor.removed).toBe(true);
    expect(navigatedTo).toBe('');
    for (const call of fetchCalls) {
      expect(call.url).not.toContain('export-token');
    }
  });

  test('refreshes the session before starting the download', async () => {
    await exportBackup('file-456');
    expect(fetchCalls.map((c) => c.url)).toEqual(['/api/refresh']);
  });

  test('does not start a download without a session', async () => {
    cookieValue = '';
    await exportBackup('file-no-session');
    expect(createdAnchors.length).toBe(0);
    expect(lastAlert).toContain('session has expired');
  });

  test('encodes the file id in the export URL', () => {
    expect(exportUrl('a/b?c')).toBe('/api/files/a%2Fb%3Fc/export');
  });

  test('pacing constant is a short fixed delay', () => {
    expect(EXPORT_DOWNLOAD_PACING_MS).toBeGreaterThan(0);
    expect(EXPORT_DOWNLOAD_PACING_MS).toBeLessThanOrEqual(1000);
  });
});
