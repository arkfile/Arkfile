/**
 * Retry Handler for Chunked Transfers
 *
 * Exponential backoff retry for chunk upload and download HTTP calls.
 * Shared policy: retry network errors, 408, 429, and 5xx up to maxRetries.
 */

/**
 * Configuration for retry behavior
 */
export interface RetryConfig {
  /** Maximum number of retry attempts after the first try (default: 3) */
  maxRetries: number;
  /** Initial delay in milliseconds (default: 1000) */
  initialDelayMs: number;
  /** Maximum delay in milliseconds (default: 30000) */
  maxDelayMs: number;
  /** Backoff multiplier (default: 2) */
  backoffMultiplier: number;
  /** Add jitter to delays to prevent thundering herd (default: true) */
  jitter: boolean;
}

/**
 * Default retry configuration
 */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  initialDelayMs: 1000,
  maxDelayMs: 30000,
  backoffMultiplier: 2,
  jitter: true,
};

/**
 * Result of a retry operation
 */
export interface RetryResult<T> {
  success: boolean;
  data?: T | undefined;
  error?: Error | undefined;
  attempts: number;
}

/**
 * Determines if an error is retryable
 *
 * @param error - The error to check
 * @returns true if the error is retryable
 */
export function isRetryableError(error: unknown): boolean {
  if (error instanceof DOMException && error.name === 'AbortError') {
    return false;
  }
  if (error instanceof Error && error.name === 'AbortError') {
    return false;
  }

  // Network errors are retryable
  if (error instanceof TypeError && error.message.includes('fetch')) {
    return true;
  }

  // Check for specific HTTP status codes
  if (error instanceof Response) {
    const status = error.status;
    // Retry on server errors (5xx) and rate limiting (429)
    // Don't retry on client errors (4xx) except 429 / 408
    return status >= 500 || status === 429 || status === 408;
  }

  // Check for error objects with status property
  if (error && typeof error === 'object' && 'status' in error) {
    const status = (error as { status: number }).status;
    return status >= 500 || status === 429 || status === 408;
  }

  return false;
}

/**
 * Calculate delay for next retry attempt with exponential backoff
 *
 * @param attempt - Current attempt number (0-indexed)
 * @param config - Retry configuration
 * @returns Delay in milliseconds
 */
export function calculateDelay(attempt: number, config: RetryConfig): number {
  // Exponential backoff: initialDelay * (multiplier ^ attempt)
  let delay = config.initialDelayMs * Math.pow(config.backoffMultiplier, attempt);

  // Cap at maximum delay
  delay = Math.min(delay, config.maxDelayMs);

  // Add jitter (±25% of delay)
  if (config.jitter) {
    const jitterRange = delay * 0.25;
    delay = delay + (Math.random() * jitterRange * 2 - jitterRange);
  }

  return Math.floor(delay);
}

/**
 * Sleep for a specified duration, optionally abortable.
 *
 * @param ms - Duration in milliseconds
 * @param signal - Optional AbortSignal; rejects with AbortError if aborted
 */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    return Promise.reject(new DOMException('Aborted', 'AbortError'));
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (signal) {
        signal.removeEventListener('abort', onAbort);
      }
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('Aborted', 'AbortError'));
    };
    if (signal) {
      signal.addEventListener('abort', onAbort, { once: true });
    }
  });
}

/**
 * Execute a function with retry logic
 *
 * @param fn - The async function to execute
 * @param config - Retry configuration (optional, uses defaults)
 * @param onRetry - Optional callback called before each retry
 * @param signal - Optional AbortSignal; stops backoff and fails if aborted
 * @returns Promise resolving to the result
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  config: Partial<RetryConfig> = {},
  onRetry?: (attempt: number, error: Error, delayMs: number) => void,
  signal?: AbortSignal,
): Promise<RetryResult<T>> {
  const fullConfig: RetryConfig = { ...DEFAULT_RETRY_CONFIG, ...config };
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= fullConfig.maxRetries; attempt++) {
    if (signal?.aborted) {
      return {
        success: false,
        error: new DOMException('Aborted', 'AbortError'),
        attempts: attempt + 1,
      };
    }
    try {
      const data = await fn();
      return {
        success: true,
        data,
        attempts: attempt + 1,
      };
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (signal?.aborted || !isRetryableError(error)) {
        break;
      }

      // Check if we should retry
      if (attempt < fullConfig.maxRetries) {
        const delay = calculateDelay(attempt, fullConfig);

        if (onRetry) {
          onRetry(attempt + 1, lastError, delay);
        }

        try {
          await sleep(delay, signal);
        } catch (sleepErr) {
          lastError = sleepErr instanceof Error ? sleepErr : new Error(String(sleepErr));
          break;
        }
      } else {
        break;
      }
    }
  }

  return {
    success: false,
    error: lastError,
    attempts: fullConfig.maxRetries + 1,
  };
}

/**
 * Fetch with retry logic
 *
 * @param url - URL to fetch
 * @param options - Fetch options
 * @param retryConfig - Retry configuration
 * @param onRetry - Optional callback called before each retry
 * @returns Promise resolving to the Response
 */
export async function fetchWithRetry(
  url: string,
  options: RequestInit = {},
  retryConfig: Partial<RetryConfig> = {},
  onRetry?: (attempt: number, error: Error, delayMs: number) => void
): Promise<Response> {
  const result = await withRetry(
    async () => {
      const response = await fetch(url, options);

      // Throw on error status codes to trigger retry logic
      if (!response.ok) {
        const error = new Error(`HTTP ${response.status}: ${response.statusText}`);
        (error as Error & { status: number }).status = response.status;
        throw error;
      }

      return response;
    },
    retryConfig,
    onRetry,
    options.signal ?? undefined,
  );

  if (!result.success || !result.data) {
    throw result.error || new Error('Request failed after retries');
  }

  return result.data;
}

/**
 * Download a chunk with retry logic
 *
 * @param url - Chunk URL
 * @param headers - Request headers (e.g., Authorization)
 * @param retryConfig - Retry configuration
 * @param onRetry - Optional callback called before each retry
 * @param signal - Optional AbortSignal
 * @returns Promise resolving to the chunk data as Uint8Array
 */
export async function downloadChunkWithRetry(
  url: string,
  headers: Record<string, string> = {},
  retryConfig: Partial<RetryConfig> = {},
  onRetry?: (attempt: number, error: Error, delayMs: number) => void,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const init: RequestInit = { headers };
  if (signal) {
    init.signal = signal;
  }
  const response = await fetchWithRetry(
    url,
    init,
    retryConfig,
    onRetry
  );

  const arrayBuffer = await response.arrayBuffer();
  return new Uint8Array(arrayBuffer);
}
