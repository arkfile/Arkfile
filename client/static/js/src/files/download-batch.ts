/**
 * Multi-file download orchestration for the owner vault.
 *
 * Sequential only. Account-password files run first; custom-password files
 * follow with per-attempt password prompts (2 minute wait, 3 attempts per
 * round, 3 rounds max). Secrets are disposed on every path.
 */

import { isAuthenticated, refreshToken } from '../utils/auth.js';
import { showError, showSuccess, showWarning } from '../ui/messages.js';
import { showProgress, updateProgress, hideProgress } from '../ui/progress.js';
import { showPasswordPrompt, hidePasswordPrompt } from '../ui/password-modal.js';
import { downloadFile } from './download.js';
import { reserveBasenames } from './output-basename.js';

const CUSTOM_PASSWORD_PROMPT_MS = 2 * 60 * 1000;
const MAX_PASSWORD_ATTEMPTS_PER_ROUND = 3;
const MAX_ROUNDS = 3;

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

async function listDirectoryFileNames(directory: FileSystemDirectoryHandle): Promise<string[]> {
  const names: string[] = [];
  // entries() is present on Chromium File System Access directory handles.
  const iterable = directory as FileSystemDirectoryHandle & {
    entries?: () => AsyncIterableIterator<[string, FileSystemHandle]>;
  };
  if (typeof iterable.entries !== 'function') {
    return names;
  }
  for await (const [name, handle] of iterable.entries()) {
    if (handle.kind === 'file') {
      names.push(name);
    }
  }
  return names;
}

async function ensureFreshBatchAuth(): Promise<void> {
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
  abortSignal?: AbortSignal,
): Promise<{ password: string } | { reason: BatchDownloadFailureReason }> {
  if (abortSignal?.aborted) {
    return { reason: 'cancelled' };
  }

  const abortPromise = abortSignal
    ? new Promise<{ reason: BatchDownloadFailureReason }>((resolve) => {
        const onAbort = () => {
          hidePasswordPrompt();
          resolve({ reason: 'cancelled' });
        };
        if (abortSignal.aborted) {
          onAbort();
          return;
        }
        abortSignal.addEventListener('abort', onAbort, { once: true });
      })
    : null;

  const promptPromise = showPasswordPrompt({
    title: 'File Password Required',
    message: `Enter the custom password for "${filename}". Waiting up to 2 minutes.`,
    ...(hint ? { hint } : {}),
    showCacheDuration: false,
    submitLabel: 'Decrypt',
    cancelLabel: 'Skip file',
    timeoutMs: CUSTOM_PASSWORD_PROMPT_MS,
  }).then((result) => {
    if (result === 'timeout') {
      return { reason: 'prompt_timeout' as const };
    }
    if (!result) {
      return { reason: 'prompt_cancelled' as const };
    }
    return { password: result.password };
  });

  if (abortPromise) {
    return await Promise.race([promptPromise, abortPromise]);
  }
  return await promptPromise;
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

function classifyDownloadError(err: unknown): BatchDownloadFailureReason {
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
 * Download the provided vault files using the batch state machine.
 * Directory picker is attempted under the user gesture of the caller when
 * available; otherwise files use the normal browser download path.
 */
export async function downloadSelectedFiles(
  entries: readonly BatchDownloadSourceFile[],
): Promise<BatchDownloadResult> {
  const targets = entries.map(toTarget);
  if (targets.length === 0) {
    showError('No files selected for download.');
    return { rounds: [], cancelled: false };
  }

  let directoryHandle: FileSystemDirectoryHandle | undefined;
  try {
    if (typeof window !== 'undefined' && 'showDirectoryPicker' in window) {
      directoryHandle = await (
        window as Window & {
          showDirectoryPicker: (opts?: { mode?: string }) => Promise<FileSystemDirectoryHandle>;
        }
      ).showDirectoryPicker({ mode: 'readwrite' });
    } else {
      console.info(
        '[arkfile-download-batch] Folder picker unavailable; using browser download folder. The browser may ask permission for multiple downloads or block them.',
      );
    }
  } catch {
    console.info(
      '[arkfile-download-batch] No download folder chosen; using browser download folder.',
    );
  }

  let alreadyTaken: string[] = [];
  if (directoryHandle) {
    try {
      alreadyTaken = await listDirectoryFileNames(directoryHandle);
    } catch (err) {
      console.warn('[arkfile-download-batch] Failed to list directory entries:', err);
    }
  }

  // Reserve basenames so collision suffixes stay stable across retries.
  const reserved = reserveBasenames(
    targets.map((t) => ({ key: t.file_id, filename: t.filename })),
    alreadyTaken,
  );

  const abortController = new AbortController();
  const result: BatchDownloadResult = { rounds: [], cancelled: false };
  let pending = targets.slice();
  let fatalAuth = false;

  for (let round = 1; round <= MAX_ROUNDS && pending.length > 0; round++) {
    if (abortController.signal.aborted || fatalAuth) {
      result.cancelled = true;
      break;
    }

    showProgress({
      title: `Downloading files (round ${round})`,
      message: `${pending.length} file(s) remaining`,
      indeterminate: true,
      allowCancel: true,
      onCancel: () => {
        abortController.abort();
        hidePasswordPrompt();
      },
    });

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

      updateProgress({
        message: `Account file ${i + 1} of ${account.length}: ${file.filename}`,
      });

      try {
        await ensureFreshBatchAuth();
        await downloadFile(file.file_id, file.password_hint, file.sha256sum, file.password_type, {
          throwOnFailure: true,
          abortController,
          showProgressUI: false,
          ...(directoryHandle
            ? {
                directoryHandle,
                reservedFilename: reserved.get(file.file_id) || file.filename,
              }
            : {}),
        });
        summary.accountSucceeded.push({
          fileId: file.file_id,
          filename: file.filename,
          passwordType: 'account',
        });
      } catch (err) {
        const reason = classifyDownloadError(err);
        if (reason === 'auth_expired') {
          fatalAuth = true;
          aborting = true;
          summary.accountFailed.push({
            fileId: file.file_id,
            filename: file.filename,
            passwordType: 'account',
            reason,
          });
          markSkippedRest(account.slice(i + 1), 'skipped');
          markSkippedRest(custom, 'skipped');
          break;
        }
        if (reason === 'cancelled') {
          aborting = true;
          summary.accountFailed.push({
            fileId: file.file_id,
            filename: file.filename,
            passwordType: 'account',
            reason,
          });
          markSkippedRest(account.slice(i + 1), 'cancelled');
          markSkippedRest(custom, 'cancelled');
          break;
        }
        summary.accountFailed.push({
          fileId: file.file_id,
          filename: file.filename,
          passwordType: 'account',
          reason,
        });
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

        updateProgress({
          message: `Custom-password file ${i + 1} of ${custom.length}: ${file.filename}`,
        });

        let succeeded = false;
        let lastReason: BatchDownloadFailureReason = 'download_failed';

        for (let attempt = 1; attempt <= MAX_PASSWORD_ATTEMPTS_PER_ROUND; attempt++) {
          if (abortController.signal.aborted) {
            lastReason = 'cancelled';
            break;
          }

          const promptResult = await promptCustomPasswordWithTimeout(
            file.filename,
            file.password_hint,
            abortController.signal,
          );

          if ('reason' in promptResult) {
            lastReason = promptResult.reason;
            if (
              promptResult.reason === 'cancelled' ||
              promptResult.reason === 'prompt_cancelled'
            ) {
              break;
            }
            // prompt_timeout: count as an attempt and continue
            continue;
          }

          let password = promptResult.password;
          try {
            await ensureFreshBatchAuth();
            await downloadFile(file.file_id, file.password_hint, file.sha256sum, file.password_type, {
              customPassword: password,
              throwOnFailure: true,
              abortController,
              showProgressUI: false,
              ...(directoryHandle
                ? {
                    directoryHandle,
                    reservedFilename: reserved.get(file.file_id) || file.filename,
                  }
                : {}),
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

    hideProgress();
    result.rounds.push(summary);
    showSuccess(formatRoundSummary(summary));

    if (abortController.signal.aborted) {
      result.cancelled = true;
      break;
    }
    if (fatalAuth) {
      result.cancelled = true;
      showError('Session expired during batch download. Remaining files were skipped.');
      break;
    }

    const failedIds = new Set(
      [...summary.accountFailed, ...summary.customFailed].map((f) => f.fileId),
    );
    // Do not retry files skipped due to cancel/auth; only true per-file failures.
    pending = pending.filter((t) => failedIds.has(t.file_id));

    if (pending.length === 0 || round >= MAX_ROUNDS) {
      break;
    }

    const retry = window.confirm(
      `${pending.length} file(s) failed in round ${round}. Retry failed downloads?`,
    );
    if (!retry) {
      break;
    }
  }

  const last = result.rounds[result.rounds.length - 1];
  if (last) {
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
  }

  return result;
}
