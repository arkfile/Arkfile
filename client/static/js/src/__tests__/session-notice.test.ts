/**
 * Unit Tests -- 24-hour batch session notices (utils/auth.ts).
 */

import { resetMocks } from './setup';
import { describe, test, expect, beforeEach } from 'bun:test';
import {
  AuthManager,
  absoluteBatchNotice,
  noteAbsoluteBatchEnd,
} from '../utils/auth';

beforeEach(() => {
  resetMocks();
  AuthManager.clearAllSessionData();
});

describe('absoluteBatchNotice', () => {
  test('previous file finished with files still queued', () => {
    expect(absoluteBatchNotice('download', 'finished', 3)).toBe(
      'Your session ended 24 hours after you signed in. The download in progress finished. '
        + '3 other files in the queue were not downloaded. Please log in again.',
    );
  });

  test('single queued file uses the singular sentence', () => {
    expect(absoluteBatchNotice('upload', 'finished', 1)).toBe(
      'Your session ended 24 hours after you signed in. The upload in progress finished. '
        + '1 other file in the queue was not uploaded. Please log in again.',
    );
  });

  test('finished with nothing queued omits the queue sentence', () => {
    expect(absoluteBatchNotice('export', 'finished', 0)).toBe(
      'Your session ended 24 hours after you signed in. The export in progress finished. Please log in again.',
    );
  });

  test('file cut off mid-transfer', () => {
    expect(absoluteBatchNotice('download', 'interrupted', 2)).toBe(
      'Your session ended 24 hours after you signed in. The file in progress did not finish. '
        + '2 other files in the queue were not started. Please log in again.',
    );
  });

  test('first file refused before anything finished', () => {
    expect(absoluteBatchNotice('upload', 'none', 2)).toBe(
      'Your session ended 24 hours after you signed in. 2 files in the queue were not uploaded. Please log in again.',
    );
  });

  test('native export reports only files not started', () => {
    expect(absoluteBatchNotice('export', 'none', 3, true)).toBe(
      'Your session ended 24 hours after you signed in. 3 selected files were not started. Please log in again.',
    );
    expect(absoluteBatchNotice('export', 'none', 0, true)).toBe(
      'Your session ended 24 hours after you signed in. Please log in again.',
    );
  });
});

describe('noteAbsoluteBatchEnd', () => {
  test('replaces the one-shot notice for a session_absolute error', () => {
    const err = Object.assign(new Error('auth_expired'), { code: 'session_absolute' });
    noteAbsoluteBatchEnd(err, 'download', 'finished', 2);
    expect(AuthManager.consumeSessionNotice()).toContain('2 other files in the queue were not downloaded');
    expect(AuthManager.consumeSessionNotice()).toBeNull();
  });

  test('leaves the notice alone for other session codes and plain failures', () => {
    noteAbsoluteBatchEnd(Object.assign(new Error('auth_expired'), { code: 'session_idle' }), 'upload', 'finished', 2);
    noteAbsoluteBatchEnd(new Error('network'), 'upload', 'finished', 2);
    expect(AuthManager.consumeSessionNotice()).toBeNull();
  });
});
