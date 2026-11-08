import { resetMocks } from './setup';
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import {
  describeInvoiceStatus,
  isFinalInvoiceStatus,
  safeCheckoutURL,
  watchInvoiceStatus,
} from '../ui/billing';

let originalFetch: typeof globalThis.fetch;

function invoiceResponses(statuses: Array<string | number>): () => number {
  let i = 0;
  globalThis.fetch = (async (url: string) => {
    if (String(url) === '/api/refresh') {
      return new Response('{}', { status: 401 });
    }
    const next = statuses[Math.min(i, statuses.length - 1)];
    i++;
    if (typeof next === 'number') {
      return new Response('{}', { status: next });
    }
    return new Response(JSON.stringify({ data: { invoice_id: 'inv_1', status: next } }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as typeof fetch;
  return () => i;
}

const noSleep = async () => {};

beforeEach(() => {
  resetMocks();
  originalFetch = globalThis.fetch;
  (globalThis as any).document = { cookie: '', visibilityState: 'visible', addEventListener(): void {} };
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('watchInvoiceStatus', () => {
  test('reports pending, confirming, then paid and stops', async () => {
    const calls = invoiceResponses(['pending', 'pending', 'confirming', 'confirming', 'paid', 'paid']);
    const seen: string[] = [];
    const outcome = await watchInvoiceStatus('inv_1', { sleep: noSleep, onStatus: (d) => seen.push(d.status) });
    expect(outcome).toBe('paid');
    expect(seen).toEqual(['pending', 'confirming', 'paid']);
    expect(calls()).toBe(5);
  });

  test('stops on expired and failed', async () => {
    invoiceResponses(['pending', 'expired']);
    expect(await watchInvoiceStatus('inv_1', { sleep: noSleep })).toBe('expired');
    invoiceResponses(['confirming', 'failed']);
    expect(await watchInvoiceStatus('inv_1', { sleep: noSleep })).toBe('failed');
  });

  test('keeps polling through transient errors', async () => {
    invoiceResponses([500, 503, 'confirming', 'paid']);
    expect(await watchInvoiceStatus('inv_1', { sleep: noSleep })).toBe('paid');
  });

  test('stops when the session ends or the invoice is unknown', async () => {
    invoiceResponses([401]);
    expect(await watchInvoiceStatus('inv_1', { sleep: noSleep })).toBe('session_ended');
    invoiceResponses([404]);
    expect(await watchInvoiceStatus('inv_1', { sleep: noSleep })).toBe('not_found');
  });

  test('times out at the deadline', async () => {
    invoiceResponses(['pending']);
    let t = 0;
    const outcome = await watchInvoiceStatus('inv_1', {
      maxMs: 30_000,
      intervalMs: 5_000,
      now: () => t,
      sleep: async (ms) => { t += ms; },
    });
    expect(outcome).toBe('timeout');
  });

  test('stops when cancelled', async () => {
    invoiceResponses(['pending']);
    let n = 0;
    const outcome = await watchInvoiceStatus('inv_1', { sleep: noSleep, isCancelled: () => ++n > 3 });
    expect(outcome).toBe('cancelled');
  });
});

describe('invoice status helpers', () => {
  test('final statuses', () => {
    expect(isFinalInvoiceStatus('paid')).toBe(true);
    expect(isFinalInvoiceStatus('expired')).toBe(true);
    expect(isFinalInvoiceStatus('failed')).toBe(true);
    expect(isFinalInvoiceStatus('pending')).toBe(false);
    expect(isFinalInvoiceStatus('confirming')).toBe(false);
  });

  test('confirming text says the payment was detected but not yet credited', () => {
    expect(describeInvoiceStatus('confirming')).toContain('Payment detected');
    expect(describeInvoiceStatus('expired')).toContain('No balance was credited');
  });

  test('checkout links must be http or https', () => {
    expect(safeCheckoutURL('https://pay.example.com/i/abc')).toBe('https://pay.example.com/i/abc');
    expect(safeCheckoutURL('javascript:alert(1)')).toBeNull();
    expect(safeCheckoutURL('not a url')).toBeNull();
    expect(safeCheckoutURL(undefined)).toBeNull();
  });
});
