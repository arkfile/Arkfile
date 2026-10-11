/**
 * Unit Tests -- multi-file download state machine (download-batch.ts).
 */

import './setup';
import { describe, test, expect } from 'bun:test';
import {
  MAX_PASSWORD_ATTEMPTS_PER_ROUND,
  MAX_ROUNDS,
  classifyDownloadError,
  runDownloadBatch,
  type BatchDownloadEnvironment,
  type BatchDownloadSourceFile,
  type BatchDownloadTarget,
  type BatchDownloadOneOptions,
  type CustomPasswordPromptResult,
} from '../files/download-batch';

const account = (id: string): BatchDownloadSourceFile => ({
  file_id: id,
  filename: `${id}.bin`,
  password_type: 'account',
  password_hint: '',
  sha256sum: '',
});

const custom = (id: string, hint = ''): BatchDownloadSourceFile => ({
  file_id: id,
  filename: `${id}.bin`,
  password_type: 'custom',
  password_hint: hint,
  sha256sum: '',
});

interface Log {
  downloads: { id: string; password?: string; reservedFilename?: string }[];
  prompts: { filename: string; hint: string }[];
  retries: number;
  ensureAuth: number;
  finished: boolean;
}

function makeEnv(
  overrides: Partial<BatchDownloadEnvironment> & {
    download?: (target: BatchDownloadTarget, opts: BatchDownloadOneOptions, attempt: number) => Promise<void>;
    prompt?: (filename: string, call: number) => Promise<CustomPasswordPromptResult>;
    retry?: boolean;
  },
  log: Log,
): BatchDownloadEnvironment {
  const { download, prompt, retry, ...rest } = overrides;
  const attempts = new Map<string, number>();
  return {
    pickDirectory: async () => undefined,
    listDirectoryNames: async () => [],
    downloadOne: async (target, opts) => {
      const attempt = (attempts.get(target.file_id) ?? 0) + 1;
      attempts.set(target.file_id, attempt);
      log.downloads.push({
        id: target.file_id,
        ...(opts.customPassword !== undefined ? { password: opts.customPassword } : {}),
        ...(opts.reservedFilename !== undefined ? { reservedFilename: opts.reservedFilename } : {}),
      });
      if (download) {
        await download(target, opts, attempt);
      }
    },
    promptCustomPassword: async (filename, hint) => {
      log.prompts.push({ filename, hint });
      if (prompt) {
        return prompt(filename, log.prompts.length);
      }
      return { password: 'custom-secret' };
    },
    ensureAuth: async () => {
      log.ensureAuth++;
    },
    confirmRetry: () => {
      log.retries++;
      return retry ?? false;
    },
    onRoundStart: () => {},
    onProgress: () => {},
    onRoundEnd: () => {},
    onFinished: () => {
      log.finished = true;
    },
    abortController: new AbortController(),
    ...rest,
  };
}

const newLog = (): Log => ({ downloads: [], prompts: [], retries: 0, ensureAuth: 0, finished: false });

describe('runDownloadBatch', () => {
  test('downloads account files before custom files, refreshing auth before each file', async () => {
    const log = newLog();
    const result = await runDownloadBatch(
      [custom('c1'), account('a1'), custom('c2'), account('a2')],
      makeEnv({}, log),
    );
    expect(log.downloads.map((d) => d.id)).toEqual(['a1', 'a2', 'c1', 'c2']);
    expect(log.ensureAuth).toBe(4);
    expect(result.cancelled).toBe(false);
    expect(result.rounds.length).toBe(1);
    expect(result.rounds[0]!.accountSucceeded.length).toBe(2);
    expect(result.rounds[0]!.customSucceeded.length).toBe(2);
    expect(log.finished).toBe(true);
  });

  test('custom prompt shows the hint and passes the password to that attempt only', async () => {
    const log = newLog();
    await runDownloadBatch([custom('c1', 'blue door')], makeEnv({}, log));
    expect(log.prompts).toEqual([{ filename: 'c1.bin', hint: 'blue door' }]);
    expect(log.downloads).toEqual([{ id: 'c1', password: 'custom-secret' }]);
  });

  test('wrong custom passwords retry up to the attempt budget, then fail the file', async () => {
    const log = newLog();
    const result = await runDownloadBatch(
      [custom('c1')],
      makeEnv({ download: async () => { throw new Error('wrong_custom_password'); } }, log),
    );
    expect(log.prompts.length).toBe(MAX_PASSWORD_ATTEMPTS_PER_ROUND);
    expect(result.rounds[0]!.customFailed).toEqual([
      { fileId: 'c1', filename: 'c1.bin', passwordType: 'custom', reason: 'wrong_custom_password' },
    ]);
  });

  test('a prompt timeout counts as an attempt and never starts a download', async () => {
    const log = newLog();
    const result = await runDownloadBatch(
      [custom('c1')],
      makeEnv({ prompt: async () => ({ reason: 'prompt_timeout' }) }, log),
    );
    expect(log.prompts.length).toBe(MAX_PASSWORD_ATTEMPTS_PER_ROUND);
    expect(log.downloads.length).toBe(0);
    expect(result.rounds[0]!.customFailed[0]!.reason).toBe('prompt_timeout');
  });

  test('skipping one custom prompt fails only that file; the batch continues', async () => {
    const log = newLog();
    const result = await runDownloadBatch(
      [custom('c1'), custom('c2')],
      makeEnv({
        prompt: async (filename) => (filename === 'c1.bin' ? { reason: 'prompt_cancelled' } : { password: 'pw' }),
      }, log),
    );
    expect(log.downloads.map((d) => d.id)).toEqual(['c2']);
    expect(result.rounds[0]!.customFailed[0]!.reason).toBe('prompt_cancelled');
    expect(result.rounds[0]!.customSucceeded.map((f) => f.fileId)).toEqual(['c2']);
    expect(result.cancelled).toBe(false);
  });

  test('retries only failed files and never a succeeded one', async () => {
    const log = newLog();
    const result = await runDownloadBatch(
      [account('a1'), account('a2')],
      makeEnv({
        retry: true,
        download: async (target, _opts, attempt) => {
          if (target.file_id === 'a1' && attempt === 1) throw new Error('network error');
        },
      }, log),
    );
    expect(log.downloads.map((d) => d.id)).toEqual(['a1', 'a2', 'a1']);
    expect(log.retries).toBe(1);
    expect(result.rounds.length).toBe(2);
    expect(result.rounds[1]!.accountSucceeded.map((f) => f.fileId)).toEqual(['a1']);
  });

  test('stops after the maximum number of rounds', async () => {
    const log = newLog();
    const result = await runDownloadBatch(
      [account('a1')],
      makeEnv({ retry: true, download: async () => { throw new Error('network error'); } }, log),
    );
    expect(result.rounds.length).toBe(MAX_ROUNDS);
    expect(log.retries).toBe(MAX_ROUNDS - 1);
  });

  test('declining the retry ends the run after one round', async () => {
    const log = newLog();
    const result = await runDownloadBatch(
      [account('a1')],
      makeEnv({ retry: false, download: async () => { throw new Error('network error'); } }, log),
    );
    expect(result.rounds.length).toBe(1);
    expect(log.retries).toBe(1);
  });

  test('session loss aborts the round and skips every remaining file', async () => {
    const log = newLog();
    const result = await runDownloadBatch(
      [account('a1'), account('a2'), custom('c1')],
      makeEnv({ retry: true, download: async () => { throw new Error('auth_expired'); } }, log),
    );
    expect(log.downloads.map((d) => d.id)).toEqual(['a1']);
    expect(result.cancelled).toBe(true);
    expect(result.rounds[0]!.skipped.map((f) => f.fileId)).toEqual(['a2', 'c1']);
    expect(log.retries).toBe(0);
  });

  test('batch cancel during a download marks the rest cancelled and offers no retry', async () => {
    const log = newLog();
    const abortController = new AbortController();
    const result = await runDownloadBatch(
      [account('a1'), account('a2'), custom('c1')],
      makeEnv({
        abortController,
        retry: true,
        download: async () => {
          abortController.abort();
          throw new Error('Download cancelled');
        },
      }, log),
    );
    expect(log.downloads.map((d) => d.id)).toEqual(['a1']);
    expect(log.prompts.length).toBe(0);
    expect(result.cancelled).toBe(true);
    expect(result.rounds[0]!.skipped.every((f) => f.reason === 'cancelled')).toBe(true);
    expect(log.retries).toBe(0);
  });

  test('batch cancel while a custom prompt is open stops the run', async () => {
    const log = newLog();
    const abortController = new AbortController();
    const result = await runDownloadBatch(
      [custom('c1'), custom('c2')],
      makeEnv({
        abortController,
        prompt: async () => {
          abortController.abort();
          return { reason: 'cancelled' };
        },
      }, log),
    );
    expect(log.prompts.length).toBe(1);
    expect(log.downloads.length).toBe(0);
    expect(result.cancelled).toBe(true);
    expect(result.rounds[0]!.skipped.map((f) => f.fileId)).toEqual(['c2']);
  });

  test('custom passwords are not retained in the batch result', async () => {
    const log = newLog();
    const result = await runDownloadBatch(
      [custom('c1'), custom('c2')],
      makeEnv({
        prompt: async (_name, call) => ({ password: `secret-${call}` }),
        download: async (target) => {
          if (target.file_id === 'c2') throw new Error('wrong_custom_password');
        },
      }, log),
    );
    const serialized = JSON.stringify(result);
    expect(serialized.includes('secret-')).toBe(false);
  });

  test('directory downloads reserve collision-free names that retries reuse', async () => {
    const log = newLog();
    const dir = {} as FileSystemDirectoryHandle;
    await runDownloadBatch(
      [
        { ...account('a1'), filename: 'photo.png' },
        { ...account('a2'), filename: 'photo.png' },
      ],
      makeEnv({
        pickDirectory: async () => dir,
        listDirectoryNames: async () => ['Photo.png'],
        retry: true,
        download: async (target, _opts, attempt) => {
          if (target.file_id === 'a1' && attempt === 1) throw new Error('network error');
        },
      }, log),
    );
    const names = log.downloads.map((d) => `${d.id}:${d.reservedFilename}`);
    expect(names).toEqual(['a1:photo-1.png', 'a2:photo-2.png', 'a1:photo-1.png']);
  });

  test('an empty selection does nothing', async () => {
    const log = newLog();
    const result = await runDownloadBatch([], makeEnv({}, log));
    expect(result.rounds.length).toBe(0);
    expect(log.downloads.length).toBe(0);
  });
});

describe('classifyDownloadError', () => {
  test('maps known failures to stable reasons', () => {
    expect(classifyDownloadError(new Error('auth_expired'))).toBe('auth_expired');
    expect(classifyDownloadError(new Error('Download cancelled'))).toBe('cancelled');
    expect(classifyDownloadError(new Error('Please check your password'))).toBe('wrong_custom_password');
    expect(classifyDownloadError(new Error('integrity_mismatch: digest'))).toBe('integrity_mismatch');
    expect(classifyDownloadError(undefined)).toBe('download_failed');
  });
});
