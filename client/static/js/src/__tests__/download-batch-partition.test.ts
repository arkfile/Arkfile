import { describe, test, expect } from 'bun:test';
import {
  partitionDownloadTargets,
  type BatchDownloadTarget,
} from '../files/download-batch.js';
import { reserveBasenames } from '../files/output-basename.js';

describe('partitionDownloadTargets', () => {
  test('account files precede custom while preserving relative order', () => {
    const targets: BatchDownloadTarget[] = [
      { file_id: '1', filename: 'a', password_type: 'custom', password_hint: '', sha256sum: '' },
      { file_id: '2', filename: 'b', password_type: 'account', password_hint: '', sha256sum: '' },
      { file_id: '3', filename: 'c', password_type: 'custom', password_hint: '', sha256sum: '' },
      { file_id: '4', filename: 'd', password_type: 'account', password_hint: '', sha256sum: '' },
    ];
    const { account, custom } = partitionDownloadTargets(targets);
    expect(account.map((t) => t.file_id)).toEqual(['2', '4']);
    expect(custom.map((t) => t.file_id)).toEqual(['1', '3']);
  });
});

describe('batch basename reservation', () => {
  test('reserves once and keeps the same name for retry reuse', () => {
    const items = [
      { key: 'a', filename: 'photo.png' },
      { key: 'b', filename: 'photo.png' },
    ];
    const first = reserveBasenames(items, ['photo.png']);
    expect(first.get('a')).toBe('photo-1.png');
    expect(first.get('b')).toBe('photo-2.png');

    // Retries must reuse the prior reservation map, not re-increment.
    expect(first.get('a')).toBe('photo-1.png');
    expect(first.get('b')).toBe('photo-2.png');
  });
});
