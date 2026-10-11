/**
 * Multi-file download orchestration for the owner vault.
 *
 * Sequential only. Account-password files run first; custom-password files
 * follow with per-attempt password prompts (2 minute wait, 3 attempts per
 * round, 3 rounds max). Secrets are disposed on every path.
 *
 * The state machine (runDownloadBatch) takes its side effects through
 * BatchDownloadEnvironment so it can be unit-tested; downloadSelectedFiles
 * supplies the browser implementation.
 */

import { isAuthenticated, refreshToken } from '../utils/auth.js';
import { showError, showSuccess, showWarning } from '../ui/messages.js';
import { showProgress, updateProgress, hideProgress } from '../ui/progress.js';
import { showPasswordPrompt, hidePasswordPrompt } from '../ui/password-modal.js';
import { downloadFile } from './download.js';
import { reserveBasenames, safeOwnerBasename } from './output-basename.js';
import { listDirectoryEntryNames } from './directory-publish.js';

export const CUSTOM_PASSWORD_PROMPT_MS = 2 * 60 * 1000;
export const MAX_PASSWORD_ATTEMPTS_PER_ROUND = 3;
export const MAX_ROUNDS = 3;

export type BatchDownloadFailureReason =
  | 'wrong_custom_password'
  | 'prompt_timeout'
  | 'prompt_cancelled'
  | 'download_failed'
  | 'cancelled'
  | 'auth_expired'
  | 'skipped'
  | 'integrity_mismatch'
  | string;

/** Minimal file row shape needed for batch download (avoids importing list.ts). */
export interface BatchDownloadSourceFile {
  file_id: string;
  filename: string;
  password_type: 'account' | 'custom';
  password_hint: string;
  sha256sum: string;
}

export interface BatchDownloadTarget {
  file_id: string;
  filename: string;
  password_type: 'account' | 'custom';
  password_hint: string;
  sha256sum: string;
}

export interface BatchDownloadFileResult {
  fileId: string;
  filename: string;
  passwordType: 'account' | 'custom';
  reason?: string;
}

export interface BatchDownloadRoundSummary {
  round: number;
  accountSucceeded: BatchDownloadFileResult[];
  accountFailed: BatchDownloadFileResult[];
  customSucceeded: BatchDownloadFileResult[];
  customFailed: BatchDownloadFileResult[];
  skipped: BatchDownloadFileResult[];
}

export interface BatchDownloadResult {
  rounds: BatchDownloadRoundSummary[];
  cancelled: boolean;
}

export type CustomPasswordPromptResult =
  | { password: string }
  | { reason: BatchDownloadFailureReason };

export interface BatchDownloadOneOptions {
  customPassword?: string;
  abortController: AbortController;
  directoryHandle?: FileSystemDirectoryHandle;
  reservedFilename?: string;
}

/** Side effects of a batch download, injected so the state machine is testable. */
export interface BatchDownloadEnvironment {
  /** Ask for a destination folder; undefined means use the browser download folder. */
  pickDirectory: () => Promise<FileSystemDirectoryHandle | undefined>;
  listDirectoryNames: (dir: FileSystemDirectoryHandle) => Promise<string[]>;
  /** Download, decrypt, verify, and publish one file. Throws on failure. */
  downloadOne: (target: BatchDownloadTarget, opts: BatchDownloadOneOptions) => Promise<void>;
  promptCustomPassword: (
    filename: string,
    hint: string,
    signal: AbortSignal,
  ) => Promise<CustomPasswordPromptResult>;
  ensureAuth: () => Promise<void>;
  confirmRetry: (failedCount: number, round: number) => boolean;
  onRoundStart: (round: number, remaining: number, cancel: () => void) => void;
  onProgress: (message: string) => void;
  onRoundEnd: (summary: BatchDownloadRoundSummary) => void;
  onFinished: (result: BatchDownloadResult) => void;
  abortController: AbortController;
}

function toTarget(entry: BatchDownloadSourceFile): BatchDownloadTarget {
  return {
    file_id: entry.file_id,
    filename: entry.filename || entry.file_id,
    password_type: entry.password_type,
    password_hint: entry.password_hint || '',
    sha256sum: entry.sha256sum || '',
  };
}

export function partitionDownloadTargets(targets: BatchDownloadTarget[]): {
  account: BatchDownloadTarget[];
  custom: BatchDownloadTarget[];
} {
  const account: BatchDownloadTarget[] = [];
  const custom: BatchDownloadTarget[] = [];
  for (const t of targets) {
    if (t.password_type === 'custom') {
      custom.push(t);
    } else {
      account.push(t);
    }
  }
  return { account, custom };
}

/** Refresh the session between batch files; throws 'auth_expired' when it is gone. */
export async function ensureFreshBatchAuth(): Promise<void> {
  if (!isAuthenticated()) {
    throw new Error('auth_expired');
  }
  const refreshed = await refreshToken();
  if (!refreshed && !isAuthenticated()) {
    throw new Error('auth_expired');
  }
}

async function promptCustomPasswordWithTimeout(
  filename: string,
  hint: string,
  abortSignal: AbortSignal,
): Promise<CustomPasswordPromptResult> {
  if (abortSignal.aborted) {
    return { reason: 'cancelled' };
  }

  let removeAbortListener: () => void = () => {};
  const abortPromise = new Promise<CustomPasswordPromptResult>((resolve) => {
    const onAbort = () => {
      hidePasswordPrompt();
      resolve({ reason: 'cancelled' });
    };
    abortSignal.addEventListener('abort', onAbort, { once: true });
    removeAbortListener = () => abortSignal.removeEventListener('abort', onAbort);
  });

  const promptPromise = showPasswordPrompt({
    title: 'File Password Required',
    message: `Enter the custom password for "${filename}". Waiting up to 2 minutes.`,
    ...(hint ? { hint } : {}),
    showCacheDuration: false,
    submitLabel: 'Decrypt',
    cancelLabel: 'Skip file',
    timeoutMs: CUSTOM_PASSWORD_PROMPT_MS,
  }).then((result): CustomPasswordPromptResult => {
    if (result === 'timeout') {
      return { reason: 'prompt_timeout' };
    }
    if (!result) {
      return { reason: 'prompt_cancelled' };
    }
    return { password: result.password };
  });

  try {
    return await Promise.race([promptPromise, abortPromise]);
  } finally {
    removeAbortListener();
  }
}

function formatRoundSummary(summary: BatchDownloadRoundSummary): string {
  const lines = [
    `Round ${summary.round}:`,
    `  Account password -- succeeded: ${summary.accountSucceeded.length}, failed: ${summary.accountFailed.length}`,
    `  Custom password -- succeeded: ${summary.customSucceeded.length}, failed: ${summary.customFailed.length}`,
  ];
  if (summary.skipped.length > 0) {
    lines.push(`  Skipped (cancelled/unstarted): ${summary.skipped.length}`);
  }
  for (const f of [...summary.accountFailed, ...summary.customFailed, ...summary.skipped]) {
    lines.push(`  [X] ${f.filename}: ${f.reason || 'failed'}`);
  }
  return lines.join('\n');
}

export function classifyDownloadError(err: unknown): BatchDownloadFailureReason {
  const msg = err instanceof Error ? err.message : String(err || '');
  if (!msg) return 'download_failed';
  if (msg === 'cancelled' || /cancelled/i.test(msg)) return 'cancelled';
  if (msg === 'auth_expired' || /not authenticated/i.test(msg)) return 'auth_expired';
  if (msg.includes('wrong_custom_password') || /check your password/i.test(msg)) {
    return 'wrong_custom_password';
  }
  if (msg.includes('prompt_cancelled')) return 'prompt_cancelled';
  if (msg.includes('prompt_timeout')) return 'prompt_timeout';
  if (msg.includes('integrity_mismatch')) return 'integrity_mismatch';
  return msg || 'download_failed';
}

/**
 * Run the batch state machine over the given files. Account-password files go
 * first and custom-password files last in every round; only per-file failures
 * are retried, for at most MAX_ROUNDS rounds.
 */
export async function runDownloadBatch(
  entries: readonly BatchDownloadSourceFile[],
  env: BatchDownloadEnvironment,
): Promise<BatchDownloadResult> {
  const targets = entries.map(toTarget);
  const result: BatchDownloadResult = { rounds: [], cancelled: false };
  if (targets.length === 0) {
    return result;
  }

  const directoryHandle = await env.pickDirectory();
  let alreadyTaken: string[] = [];
  if (directoryHandle) {
    try {
      alreadyTaken = await env.listDirectoryNames(directoryHandle);
    } catch (err) {
      console.warn('[arkfile-download-batch] Failed to list directory entries:', err);
    }
  }

  // Reserve basenames so collision suffixes stay stable across retries.
  const reserved = reserveBasenames(
    targets.map((t) => ({ key: t.file_id, filename: safeOwnerBasename(t.filename, t.file_id) })),
    alreadyTaken,
  );

  const abortController = env.abortController;
  const destination = (file: BatchDownloadTarget): Partial<BatchDownloadOneOptions> =>
    directoryHandle
      ? { directoryHandle, reservedFilename: reserved.get(file.file_id) || file.filename }
      : {};

  let pending = targets.slice();
  let fatalAuth = false;

  for (let round = 1; round <= MAX_ROUNDS && pending.length > 0; round++) {
    if (abortController.signal.aborted || fatalAuth) {
      result.cancelled = true;
      break;
    }

    env.onRoundStart(round, pending.length, () => abortController.abort());

    const { account, custom } = partitionDownloadTargets(pending);
    const summary: BatchDownloadRoundSummary = {
      round,
      accountSucceeded: [],
      accountFailed: [],
      customSucceeded: [],
      customFailed: [],
      skipped: [],
    };

    let aborting = false;

    const markSkippedRest = (rest: BatchDownloadTarget[], reason: string) => {
      for (const file of rest) {
        summary.skipped.push({
          fileId: file.file_id,
          filename: file.filename,
          passwordType: file.password_type,
          reason,
        });
      }
    };

    for (let i = 0; i < account.length; i++) {
      const file = account[i]!;
      if (abortController.signal.aborted) {
        aborting = true;
        markSkippedRest(account.slice(i), 'cancelled');
        markSkippedRest(custom, 'cancelled');
        break;
      }

      env.onProgress(`Account file ${i + 1} of ${account.length}: ${file.filename}`);

      try {
        await env.ensureAuth();
        await env.downloadOne(file, { abortController, ...destination(file) });
        summary.accountSucceeded.push({
          fileId: file.file_id,
          filename: file.filename,
          passwordType: 'account',
        });
      } catch (err) {
        const reason = classifyDownloadError(err);
        summary.accountFailed.push({
          fileId: file.file_id,
          filename: file.filename,
          passwordType: 'account',
          reason,
        });
        if (reason === 'auth_expired') {
          fatalAuth = true;
          aborting = true;
          markSkippedRest(account.slice(i + 1), 'skipped');
          markSkippedRest(custom, 'skipped');
          break;
        }
        if (reason === 'cancelled') {
          aborting = true;
          markSkippedRest(account.slice(i + 1), 'cancelled');
          markSkippedRest(custom, 'cancelled');
          break;
        }
      }
    }

    if (!aborting) {
      for (let i = 0; i < custom.length; i++) {
        const file = custom[i]!;
        if (abortController.signal.aborted) {
          aborting = true;
          markSkippedRest(custom.slice(i), 'cancelled');
          break;
        }

        env.onProgress(`Custom-password file ${i + 1} of ${custom.length}: ${file.filename}`);

        let succeeded = false;
        let lastReason: BatchDownloadFailureReason = 'download_failed';

        for (let attempt = 1; attempt <= MAX_PASSWORD_ATTEMPTS_PER_ROUND; attempt++) {
          if (abortController.signal.aborted) {
            lastReason = 'cancelled';
            break;
          }

          const promptResult = await env.promptCustomPassword(
            file.filename,
            file.password_hint,
            abortController.signal,
          );

          if ('reason' in promptResult) {
            lastReason = promptResult.reason;
            if (lastReason === 'cancelled' || lastReason === 'prompt_cancelled') {
              break;
            }
            // prompt_timeout counts as an attempt.
            continue;
          }

          // The password string cannot be wiped in JavaScript; keep it in this
          // attempt's scope only and drop the reference when the attempt ends.
          let password = promptResult.password;
          try {
            await env.ensureAuth();
            await env.downloadOne(file, {
              customPassword: password,
              abortController,
              ...destination(file),
            });
            succeeded = true;
            break;
          } catch (err) {
            lastReason = classifyDownloadError(err);
            if (lastReason === 'auth_expired') {
              fatalAuth = true;
              break;
            }
            if (lastReason === 'cancelled') {
              break;
            }
            // Wrong password and other per-attempt failures continue until attempt budget.
          } finally {
            password = '';
          }
        }

        if (succeeded) {
          summary.customSucceeded.push({
            fileId: file.file_id,
            filename: file.filename,
            passwordType: 'custom',
          });
        } else {
          summary.customFailed.push({
            fileId: file.file_id,
            filename: file.filename,
            passwordType: 'custom',
            reason: lastReason,
          });
          if (lastReason === 'auth_expired' || lastReason === 'cancelled') {
            aborting = true;
            markSkippedRest(custom.slice(i + 1), lastReason === 'cancelled' ? 'cancelled' : 'skipped');
            break;
          }
        }
      }
    }

    result.rounds.push(summary);
    env.onRoundEnd(summary);

    if (abortController.signal.aborted) {
      result.cancelled = true;
      break;
    }
    if (fatalAuth) {
      result.cancelled = true;
      break;
    }

    const failedIds = new Set(
      [...summary.accountFailed, ...summary.customFailed]
        .filter((f) => f.reason !== 'cancelled')
        .map((f) => f.fileId),
    );
    // Do not retry files skipped or cancelled; only true per-file failures.
    pending = pending.filter((t) => failedIds.has(t.file_id));

    if (pending.length === 0 || round >= MAX_ROUNDS) {
      break;
    }

    if (!env.confirmRetry(pending.length, round)) {
      break;
    }
  }

  env.onFinished(result);
  return result;
}

function browserBatchEnvironment(): BatchDownloadEnvironment {
  return {
    pickDirectory: async () => {
      try {
        if (typeof window !== 'undefined' && 'showDirectoryPicker' in window) {
          return await (
            window as Window & {
              showDirectoryPicker: (opts?: { mode?: string }) => Promise<FileSystemDirectoryHandle>;
            }
          ).showDirectoryPicker({ mode: 'readwrite' });
        }
        console.info(
          '[arkfile-download-batch] Folder picker unavailable; using browser download folder. The browser may ask permission for multiple downloads or block them.',
        );
      } catch {
        console.info(
          '[arkfile-download-batch] No download folder chosen; using browser download folder.',
        );
      }
      return undefined;
    },
    listDirectoryNames: listDirectoryEntryNames,
    downloadOne: async (target, opts) => {
      await downloadFile(target.file_id, target.password_hint, target.sha256sum, target.password_type, {
        ...(opts.customPassword !== undefined ? { customPassword: opts.customPassword } : {}),
        throwOnFailure: true,
        abortController: opts.abortController,
        showProgressUI: false,
        ...(opts.directoryHandle && opts.reservedFilename
          ? { directoryHandle: opts.directoryHandle, reservedFilename: opts.reservedFilename }
          : {}),
      });
    },
    promptCustomPassword: promptCustomPasswordWithTimeout,
    ensureAuth: ensureFreshBatchAuth,
    confirmRetry: (failedCount, round) =>
      window.confirm(`${failedCount} file(s) failed in round ${round}. Retry failed downloads?`),
    onRoundStart: (round, remaining, cancel) => {
      showProgress({
        title: `Downloading files (round ${round})`,
        message: `${remaining} file(s) remaining`,
        indeterminate: true,
        allowCancel: true,
        onCancel: () => {
          cancel();
          hidePasswordPrompt();
        },
      });
    },
    onProgress: (message) => updateProgress({ message }),
    onRoundEnd: (summary) => {
      hideProgress();
      showSuccess(formatRoundSummary(summary));
    },
    onFinished: (result) => {
      const last = result.rounds[result.rounds.length - 1];
      if (!last) {
        return;
      }
      const lastRoundFailed = [...last.accountFailed, ...last.customFailed].some(
        (f) => f.reason === 'auth_expired',
      );
      if (lastRoundFailed) {
        showError('Session expired during batch download. Remaining files were skipped.');
      }
      const remaining = last.accountFailed.length + last.customFailed.length;
      if (result.cancelled) {
        showWarning('Batch download cancelled. See the round summary for details.');
      } else if (remaining > 0) {
        showWarning(
          `Batch download finished with ${remaining} unresolved failure(s). See the round summary for details.`,
        );
      } else {
        showSuccess('Batch download finished. All selected files succeeded.');
      }
    },
    abortController: new AbortController(),
  };
}

/**
 * Download the provided vault files using the batch state machine.
 * Directory picker is attempted under the user gesture of the caller when
 * available; otherwise files use the normal browser download path.
 */
export async function downloadSelectedFiles(
  entries: readonly BatchDownloadSourceFile[],
): Promise<BatchDownloadResult> {
  if (entries.length === 0) {
    showError('No files selected for download.');
    return { rounds: [], cancelled: false };
  }
  return runDownloadBatch(entries, browserBatchEnvironment());
}
