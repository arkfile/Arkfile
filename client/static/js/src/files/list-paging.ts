/**
 * Paging helpers for the cursor-paginated owner file list (GET /api/files).
 *
 * Kept free of DOM and network code so append, deduplication, and the
 * select-all-matching scan loop can be unit-tested with a mocked page source.
 */

/** Outcome of asking the list to load its next page. */
export type PageLoadResult = 'loaded' | 'busy' | 'failed';

/** Outcome of walking every remaining page. */
export type PageScanResult = 'complete' | 'stale' | 'failed';

/** Wait between checks while another page load is already in flight. */
export const PAGE_SCAN_BUSY_WAIT_MS = 50;

/** Give up waiting on an in-flight load after this many checks (30 s). */
export const PAGE_SCAN_MAX_BUSY_WAITS = 600;

/**
 * Append entries whose file_id has not been seen yet, preserving order.
 * Returns how many entries were added.
 */
export function mergeUniqueByFileId<T extends { file_id: string }>(
  seen: Set<string>,
  target: T[],
  incoming: readonly T[],
): number {
  let added = 0;
  for (const entry of incoming) {
    if (!entry.file_id || seen.has(entry.file_id)) {
      continue;
    }
    seen.add(entry.file_id);
    target.push(entry);
    added++;
  }
  return added;
}

/**
 * True when a page that reported more results failed to move the walk forward:
 * the cursor did not change or the page added no new files. Continuing would
 * request the same page forever.
 */
export function pageMadeNoProgress(
  previousCursor: string | null,
  nextCursor: string | null,
  hasMore: boolean,
  added: number,
): boolean {
  if (!hasMore) {
    return false;
  }
  return added === 0 || nextCursor === previousCursor;
}

export interface PageScanOptions {
  /** Whether the list reports another page. */
  hasMore: () => boolean;
  /** Load the next page into the list. */
  loadNext: () => Promise<PageLoadResult>;
  /** True when the scan's snapshot (filter or scan generation) is outdated. */
  isStale: () => boolean;
  /** Called after each successfully loaded page. */
  onPage: () => void;
  wait?: (ms: number) => Promise<void>;
  maxBusyWaits?: number;
}

/**
 * Load every remaining page, stopping on a stale snapshot or a failed load so a
 * network error can never spin the scan forever.
 */
export async function scanRemainingPages(opts: PageScanOptions): Promise<PageScanResult> {
  const wait = opts.wait ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const maxBusyWaits = opts.maxBusyWaits ?? PAGE_SCAN_MAX_BUSY_WAITS;
  let busyWaits = 0;

  while (opts.hasMore()) {
    if (opts.isStale()) {
      return 'stale';
    }
    const result = await opts.loadNext();
    if (result === 'failed') {
      return 'failed';
    }
    if (result === 'busy') {
      busyWaits++;
      if (busyWaits > maxBusyWaits) {
        return 'failed';
      }
      await wait(PAGE_SCAN_BUSY_WAIT_MS);
      continue;
    }
    busyWaits = 0;
    opts.onPage();
  }
  return opts.isStale() ? 'stale' : 'complete';
}
