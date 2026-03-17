/**
 * Retry Handler Unit Tests
 * 
 * Tests for files/retry-handler.ts — exponential backoff retry logic
 * for chunked downloads. All pure logic, no DOM or WASM dependencies.
 */

import { describe, test, expect } from 'bun:test';
import {
  isRetryableError,
  calculateDelay,
  sleep,
  withRetry,
  DEFAULT_RETRY_CONFIG,
  type RetryConfig,
} from '../files/retry-handler';

// ============================================================================
// isRetryableError
// ============================================================================

describe('isRetryableError', () => {
  test('returns true for TypeError with "fetch" in message', () => {
    const err = new TypeError('Failed to fetch');
    expect(isRetryableError(err)).toBe(true);
  });

  test('returns false for TypeError without "fetch" in message', () => {
    const err = new TypeError('Cannot read property of undefined');
    expect(isRetryableError(err)).toBe(false);
  });

  test('returns true for object with status 500', () => {
    expect(isRetryableError({ status: 500 })).toBe(true);
  });

  test('returns true for object with status 502', () => {
    expect(isRetryableError({ status: 502 })).toBe(true);
  });

  test('returns true for object with status 503', () => {
    expect(isRetryableError({ status: 503 })).toBe(true);
  });

  test('returns true for object with status 429 (rate limit)', () => {
    expect(isRetryableError({ status: 429 })).toBe(true);
  });

  test('returns true for object with status 408 (request timeout)', () => {
    expect(isRetryableError({ status: 408 })).toBe(true);
  });

  test('returns false for object with status 400', () => {
    expect(isRetryableError({ status: 400 })).toBe(false);
  });

  test('returns false for object with status 401', () => {
    expect(isRetryableError({ status: 401 })).toBe(false);
  });

  test('returns false for object with status 403', () => {
    expect(isRetryableError({ status: 403 })).toBe(false);
  });

  test('returns false for object with status 404', () => {
    expect(isRetryableError({ status: 404 })).toBe(false);
  });

  test('returns false for plain Error', () => {
    expect(isRetryableError(new Error('something broke'))).toBe(false);
  });

  test('returns false for null', () => {
    expect(isRetryableError(null)).toBe(false);
  });

  test('returns false for undefined', () => {
    expect(isRetryableError(undefined)).toBe(false);
  });

  test('returns false for string', () => {
    expect(isRetryableError('error')).toBe(false);
  });

  test('returns false for number', () => {
    expect(isRetryableError(42)).toBe(false);
  });
});

// ============================================================================
// calculateDelay
// ============================================================================

describe('calculateDelay', () => {
  const noJitterConfig: RetryConfig = {
    ...DEFAULT_RETRY_CONFIG,
    jitter: false,
    initialDelayMs: 1000,
    backoffMultiplier: 2,
    maxDelayMs: 30000,
    maxRetries: 5,
  };

  test('attempt 0 returns initialDelayMs (no jitter)', () => {
    expect(calculateDelay(0, noJitterConfig)).toBe(1000);
  });

  test('attempt 1 returns initialDelayMs * multiplier (no jitter)', () => {
    expect(calculateDelay(1, noJitterConfig)).toBe(2000);
  });

  test('attempt 2 returns initialDelayMs * multiplier^2 (no jitter)', () => {
    expect(calculateDelay(2, noJitterConfig)).toBe(4000);
  });

  test('attempt 3 returns initialDelayMs * multiplier^3 (no jitter)', () => {
    expect(calculateDelay(3, noJitterConfig)).toBe(8000);
  });

  test('caps at maxDelayMs (no jitter)', () => {
    const config: RetryConfig = { ...noJitterConfig, maxDelayMs: 5000 };
    // attempt 3 would be 8000, but capped at 5000
    expect(calculateDelay(3, config)).toBe(5000);
  });

  test('with jitter, delay stays within ±25% of base', () => {
    const config: RetryConfig = { ...noJitterConfig, jitter: true };
    // Run multiple times to check jitter range
    for (let i = 0; i < 50; i++) {
      const delay = calculateDelay(0, config);
      // Base is 1000, jitter ±25% → range [750, 1250]
      expect(delay).toBeGreaterThanOrEqual(750);
      expect(delay).toBeLessThanOrEqual(1250);
    }
  });

  test('with jitter, delays are not all identical', () => {
    const config: RetryConfig = { ...noJitterConfig, jitter: true };
    const delays = new Set<number>();
    for (let i = 0; i < 20; i++) {
      delays.add(calculateDelay(0, config));
    }
    // With jitter, we should get multiple distinct values
    expect(delays.size).toBeGreaterThan(1);
  });

  test('returns integer (floor)', () => {
    const config: RetryConfig = { ...noJitterConfig, jitter: true };
    for (let i = 0; i < 10; i++) {
      const delay = calculateDelay(0, config);
      expect(delay).toBe(Math.floor(delay));
    }
  });
});

// ============================================================================
// sleep
// ============================================================================

describe('sleep', () => {
  test('resolves after specified delay', async () => {
    const start = Date.now();
    await sleep(50);
    const elapsed = Date.now() - start;
    // Allow some tolerance for timer imprecision
    expect(elapsed).toBeGreaterThanOrEqual(40);
  });

  test('resolves with undefined', async () => {
    const result = await sleep(1);
    expect(result).toBeUndefined();
  });
});

// ============================================================================
// withRetry
// ============================================================================

describe('withRetry', () => {
  test('succeeds on first attempt', async () => {
    let callCount = 0;
    const result = await withRetry(async () => {
      callCount++;
      return 'ok';
    });

    expect(result.success).toBe(true);
    expect(result.data).toBe('ok');
    expect(result.attempts).toBe(1);
    expect(callCount).toBe(1);
  });

  test('retries on retryable error and succeeds on 2nd attempt', async () => {
    let callCount = 0;
    const result = await withRetry(
      async () => {
        callCount++;
        if (callCount === 1) {
          const err = new TypeError('Failed to fetch');
          throw err;
        }
        return 'recovered';
      },
      { initialDelayMs: 1, maxRetries: 3 }
    );

    expect(result.success).toBe(true);
    expect(result.data).toBe('recovered');
    expect(result.attempts).toBe(2);
    expect(callCount).toBe(2);
  });

  test('exhausts retries and returns failure', async () => {
    let callCount = 0;
    const result = await withRetry(
      async () => {
        callCount++;
        const err = new TypeError('Failed to fetch');
        throw err;
      },
      { initialDelayMs: 1, maxRetries: 2 }
    );

    expect(result.success).toBe(false);
    expect(result.error).toBeInstanceOf(TypeError);
    expect(result.attempts).toBe(3); // initial + 2 retries
    expect(callCount).toBe(3);
  });

  test('non-retryable error stops immediately (no retry)', async () => {
    let callCount = 0;
    const result = await withRetry(
      async () => {
        callCount++;
        throw new Error('not retryable');
      },
      { initialDelayMs: 1, maxRetries: 3 }
    );

    expect(result.success).toBe(false);
    expect(result.error?.message).toBe('not retryable');
    expect(result.attempts).toBe(4); // maxRetries + 1 (loop runs but breaks on non-retryable)
    expect(callCount).toBe(1); // only called once
  });

  test('onRetry callback fires with correct arguments', async () => {
    const retryArgs: Array<{ attempt: number; error: Error; delayMs: number }> = [];
    let callCount = 0;

    await withRetry(
      async () => {
        callCount++;
        if (callCount <= 2) {
          throw new TypeError('Failed to fetch');
        }
        return 'ok';
      },
      { initialDelayMs: 1, maxRetries: 3, jitter: false },
      (attempt, error, delayMs) => {
        retryArgs.push({ attempt, error, delayMs });
      }
    );

    expect(retryArgs.length).toBe(2);
    expect(retryArgs[0].attempt).toBe(1);
    expect(retryArgs[0].error.message).toBe('Failed to fetch');
    expect(retryArgs[1].attempt).toBe(2);
  });

  test('converts non-Error throws to Error objects', async () => {
    const result = await withRetry(
      async () => {
        throw 'string error';
      },
      { initialDelayMs: 1, maxRetries: 0 }
    );

    expect(result.success).toBe(false);
    expect(result.error).toBeInstanceOf(Error);
    expect(result.error?.message).toBe('string error');
  });

  test('with maxRetries: 0, only tries once', async () => {
    let callCount = 0;
    const result = await withRetry(
      async () => {
        callCount++;
        throw new TypeError('Failed to fetch');
      },
      { maxRetries: 0 }
    );

    expect(result.success).toBe(false);
    expect(callCount).toBe(1);
    expect(result.attempts).toBe(1);
  });
});

// ============================================================================
// DEFAULT_RETRY_CONFIG
// ============================================================================

describe('DEFAULT_RETRY_CONFIG', () => {
  test('has expected default values', () => {
    expect(DEFAULT_RETRY_CONFIG.maxRetries).toBe(3);
    expect(DEFAULT_RETRY_CONFIG.initialDelayMs).toBe(1000);
    expect(DEFAULT_RETRY_CONFIG.maxDelayMs).toBe(30000);
    expect(DEFAULT_RETRY_CONFIG.backoffMultiplier).toBe(2);
    expect(DEFAULT_RETRY_CONFIG.jitter).toBe(true);
  });
});
