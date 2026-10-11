import { describe, test, expect } from 'bun:test';
import {
  mergeUniqueByFileId,
  pageMadeNoProgress,
  scanRemainingPages,
  type PageLoadResult,
} from '../files/list-paging.js';

interface Row {
  file_id: string;
}

interface FakePage {
  files: Row[];
  has_more: boolean;
  next_cursor: string | null;
}

/**
 * A mocked GET /api/files page source driven the same way list.ts drives the
 * real one: fetch by cursor, merge unique rows, advance the cursor.
 */
function pagedList(pages: Record<string, FakePage>, failOn: string[] = []) {
  const state = {
    rows: [] as Row[],
    seen: new Set<string>(),
    cursor: null as string | null,
    hasMore: true,
    fetches: [] as string[],
  };
  const fetchPage = async (cursor: string | null): Promise<FakePage | null> => {
    const key = cursor ?? 'first';
    state.fetches.push(key);
    if (failOn.includes(key)) {
      return null;
    }
    return pages[key] ?? null;
  };
  const loadNext = async (): Promise<PageLoadResult> => {
    const previous = state.cursor;
    const page = await fetchPage(previous);
    if (!page) {
      return 'failed';
    }
    const added = mergeUniqueByFileId(state.seen, state.rows, page.files);
    state.hasMore = page.has_more;
    state.cursor = page.next_cursor;
    if (pageMadeNoProgress(previous, state.cursor, state.hasMore, added)) {
      state.hasMore = false;
      return 'failed';
    }
    return 'loaded';
  };
  return { state, loadNext };
}

const threePages: Record<string, FakePage> = {
  first: { files: [{ file_id: 'a' }, { file_id: 'b' }], has_more: true, next_cursor: 'c1' },
  c1: { files: [{ file_id: 'b' }, { file_id: 'c' }], has_more: true, next_cursor: 'c2' },
  c2: { files: [{ file_id: 'd' }], has_more: false, next_cursor: null },
};

describe('mergeUniqueByFileId', () => {
  test('appends new rows in order and skips duplicates across pages', () => {
    const seen = new Set<string>();
    const rows: Row[] = [];
    expect(mergeUniqueByFileId(seen, rows, [{ file_id: 'a' }, { file_id: 'b' }])).toBe(2);
    expect(mergeUniqueByFileId(seen, rows, [{ file_id: 'b' }, { file_id: 'c' }, { file_id: '' }])).toBe(1);
    expect(rows.map((r) => r.file_id)).toEqual(['a', 'b', 'c']);
  });
});

describe('pageMadeNoProgress', () => {
  test('flags a repeated cursor or an empty page that still reports more', () => {
    expect(pageMadeNoProgress('c1', 'c1', true, 3)).toBe(true);
    expect(pageMadeNoProgress('c1', 'c2', true, 0)).toBe(true);
    expect(pageMadeNoProgress('c1', 'c2', true, 2)).toBe(false);
    expect(pageMadeNoProgress('c1', null, false, 0)).toBe(false);
  });
});

describe('scanRemainingPages', () => {
  test('loads every page and stops when the list is exhausted', async () => {
    const list = pagedList(threePages);
    let pagesSeen = 0;
    const result = await scanRemainingPages({
      hasMore: () => list.state.hasMore,
      loadNext: list.loadNext,
      isStale: () => false,
      onPage: () => { pagesSeen++; },
    });
    expect(result).toBe('complete');
    expect(list.state.fetches).toEqual(['first', 'c1', 'c2']);
    expect(list.state.rows.map((r) => r.file_id)).toEqual(['a', 'b', 'c', 'd']);
    expect(pagesSeen).toBe(3);
  });

  test('a filter change mid-scan cancels without loading further pages', async () => {
    const list = pagedList(threePages);
    let stale = false;
    const result = await scanRemainingPages({
      hasMore: () => list.state.hasMore,
      loadNext: list.loadNext,
      isStale: () => stale,
      onPage: () => { stale = true; },
    });
    expect(result).toBe('stale');
    expect(list.state.fetches).toEqual(['first']);
  });

  test('a failed page load ends the scan instead of retrying forever', async () => {
    const list = pagedList(threePages, ['c1']);
    const result = await scanRemainingPages({
      hasMore: () => list.state.hasMore,
      loadNext: list.loadNext,
      isStale: () => false,
      onPage: () => {},
    });
    expect(result).toBe('failed');
    expect(list.state.fetches).toEqual(['first', 'c1']);
  });

  test('a cursor that never advances ends the scan', async () => {
    const stuck: Record<string, FakePage> = {
      first: { files: [{ file_id: 'a' }], has_more: true, next_cursor: 'c1' },
      c1: { files: [{ file_id: 'a' }], has_more: true, next_cursor: 'c1' },
    };
    const list = pagedList(stuck);
    const result = await scanRemainingPages({
      hasMore: () => list.state.hasMore,
      loadNext: list.loadNext,
      isStale: () => false,
      onPage: () => {},
    });
    expect(result).toBe('failed');
    expect(list.state.fetches.length).toBe(2);
  });

  test('waits while another load is in flight, then continues', async () => {
    const list = pagedList(threePages);
    let busyLeft = 2;
    let waits = 0;
    const result = await scanRemainingPages({
      hasMore: () => list.state.hasMore,
      loadNext: async () => {
        if (busyLeft > 0) {
          busyLeft--;
          return 'busy';
        }
        return list.loadNext();
      },
      isStale: () => false,
      onPage: () => {},
      wait: async () => { waits++; },
    });
    expect(result).toBe('complete');
    expect(waits).toBe(2);
  });

  test('an in-flight load that never finishes eventually fails the scan', async () => {
    const result = await scanRemainingPages({
      hasMore: () => true,
      loadNext: async () => 'busy',
      isStale: () => false,
      onPage: () => {},
      wait: async () => {},
      maxBusyWaits: 3,
    });
    expect(result).toBe('failed');
  });
});
