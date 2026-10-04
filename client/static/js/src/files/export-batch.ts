/**
 * Multi-file .arkbackup export for the owner vault.
 *
 * Sequential only, no passwords, no new endpoint: every bundle is one
 * cookie-authenticated GET /api/files/:fileId/export. With the directory
 * picker, each response body streams into a writable under a readable
 * reserved name (photo.png.arkbackup) and existing entries are never
 * replaced. Without the picker, bundles start as native downloads named
 * <file_id>.arkbackup; the page cannot observe their completion, so they
 * are reported as started rather than succeeded. Explicitly cancelling the
 * picker cancels the export and starts nothing.
 */

import { showError, showSuccess, showWarning } from '../ui/messages.js';
import { showProgress, updateProgress, hideProgress } from '../ui/progress.js';
import { ensureFreshBatchAuth } from './download-batch.js';
import { EXPORT_DOWNLOAD_PACING_MS, fetchExportResponse, triggerNativeExportDownload } from './export.js';
import { BasenameReserver, safeOwnerBasename } from './output-basename.js';
import { listDirectoryEntryNames, writeToDirectoryEntry } from './directory-publish.js';

const ARKBACKUP_SUFFIX = '.arkbackup';
const ARKB_MAGIC = [0x41, 0x52, 0x4b, 0x42];
/** Selections at least this large ask for confirmation after the folder is chosen. */
export const EXPORT_CONFIRM_THRESHOLD = 25;

export interface ExportBatchTarget {
  file_id: string;
  /** Decrypted filename, or '' when metadata did not decrypt. */
  filename: string;
}

export interface ExportBatchFileResult {
  fileId: string;
  filename: string;
  bundleName?: string;
  reason?: string;
}

export interface ExportBatchResult {
  mode: 'directory' | 'native' | 'cancelled';
  succeeded: ExportBatchFileResult[];
  failed: ExportBatchFileResult[];
  skipped: ExportBatchFileResult[];
  started: ExportBatchFileResult[];
}

type PickResult = FileSystemDirectoryHandle | 'unavailable' | 'cancelled';

/** Side effects, injectable so the state machine can be unit tested. */
export interface ExportBatchEnvironment {
  pickDirectory: () => Promise<PickResult>;
  fetchExport: (fileId: string, signal: AbortSignal) => Promise<Response>;
  triggerNative: (fileId: string) => void;
  ensureAuth: () => Promise<void>;
  sleep: (ms: number) => Promise<void>;
  confirm: (message: string) => boolean;
  onProgress: (message: string) => void;
  abortController: AbortController;
}

type PickerWindow = Window & {
  showDirectoryPicker?: (opts?: { mode?: string }) => Promise<FileSystemDirectoryHandle>;
};

function directoryPickerAvailable(): boolean {
  return typeof window !== 'undefined' && typeof (window as PickerWindow).showDirectoryPicker === 'function';
}

async function pickDirectoryWithBrowser(): Promise<PickResult> {
  if (!directoryPickerAvailable()) {
    return 'unavailable';
  }
  try {
    return await (window as PickerWindow).showDirectoryPicker!({ mode: 'readwrite' });
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      return 'cancelled';
    }
    console.warn('[arkfile-export-batch] Folder picker failed; using native downloads:', err);
    return 'unavailable';
  }
}

function classifyExportError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err || '');
  if (err instanceof Error && err.name === 'AbortError') return 'cancelled';
  if (msg === 'auth_expired') return 'auth_expired';
  return msg || 'export_failed';
}

function labelFor(target: ExportBatchTarget): string {
  return target.filename || target.file_id;
}

/**
 * Stream one bundle into the directory. A non-OK status, a body that does
 * not start with ARKB, or a body shorter than Content-Length fails the file.
 */
async function exportOneToDirectory(
  directory: FileSystemDirectoryHandle,
  target: ExportBatchTarget,
  reservedName: string,
  nextName: () => string,
  env: ExportBatchEnvironment,
): Promise<string> {
  const response = await env.fetchExport(target.file_id, env.abortController.signal);
  if (response.status === 401) {
    throw new Error('auth_expired');
  }
  if (!response.ok || !response.body) {
    throw new Error(`http_${response.status}`);
  }
  const declared = Number(response.headers.get('Content-Length'));
  const body = response.body;

  return writeToDirectoryEntry(directory, reservedName, nextName, async (writable) => {
    let received = 0;
    const checker = new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        for (let i = 0; i < chunk.byteLength && received + i < ARKB_MAGIC.length; i++) {
          if (chunk[i] !== ARKB_MAGIC[received + i]) {
            throw new Error('invalid_bundle');
          }
        }
        received += chunk.byteLength;
        controller.enqueue(chunk);
      },
    });
    await body.pipeThrough(checker).pipeTo(writable as unknown as WritableStream<Uint8Array>, {
      signal: env.abortController.signal,
    });
    if (received < ARKB_MAGIC.length) {
      throw new Error('invalid_bundle');
    }
    if (Number.isFinite(declared) && declared > 0 && received !== declared) {
      throw new Error('truncated_bundle');
    }
  });
}

/** Run an export over targets with the given environment. */
export async function runExportBatch(
  targets: readonly ExportBatchTarget[],
  env: ExportBatchEnvironment,
): Promise<ExportBatchResult> {
  const result: ExportBatchResult = { mode: 'cancelled', succeeded: [], failed: [], skipped: [], started: [] };
  const picked = await env.pickDirectory();
  if (picked === 'cancelled') {
    return result;
  }
  if (targets.length >= EXPORT_CONFIRM_THRESHOLD) {
    const proceed = env.confirm(
      `Export ${targets.length} encrypted backup bundles? Each bundle is the full stored object, ` +
        'which is larger than the original file because it includes padding.',
    );
    if (!proceed) {
      return result;
    }
  }

  const signal = env.abortController.signal;
  const skipRest = (rest: readonly ExportBatchTarget[], reason: string) => {
    for (const t of rest) {
      result.skipped.push({ fileId: t.file_id, filename: labelFor(t), reason });
    }
  };

  if (picked === 'unavailable') {
    result.mode = 'native';
    for (let i = 0; i < targets.length; i++) {
      const t = targets[i]!;
      if (signal.aborted) {
        skipRest(targets.slice(i), 'cancelled');
        break;
      }
      env.onProgress(`Starting download ${i + 1} of ${targets.length}: ${labelFor(t)}`);
      try {
        await env.ensureAuth();
      } catch {
        skipRest(targets.slice(i), 'auth_expired');
        break;
      }
      env.triggerNative(t.file_id);
      result.started.push({ fileId: t.file_id, filename: labelFor(t), bundleName: `${t.file_id}${ARKBACKUP_SUFFIX}` });
      if (i < targets.length - 1) {
        await env.sleep(EXPORT_DOWNLOAD_PACING_MS);
      }
    }
    return result;
  }

  result.mode = 'directory';
  const directory = picked;
  let existing: string[] = [];
  try {
    existing = await listDirectoryEntryNames(directory);
  } catch (err) {
    console.warn('[arkfile-export-batch] Failed to list directory entries:', err);
  }
  const reserver = new BasenameReserver(existing, ARKBACKUP_SUFFIX);
  const desiredNames = new Map<string, string>();
  const reserved = new Map<string, string>();
  for (const t of targets) {
    const desired = t.filename ? safeOwnerBasename(t.filename, t.file_id) : t.file_id;
    desiredNames.set(t.file_id, desired);
    reserved.set(t.file_id, reserver.reserve(desired));
  }

  const runPass = async (work: readonly ExportBatchTarget[]): Promise<ExportBatchFileResult[]> => {
    const failures: ExportBatchFileResult[] = [];
    for (let i = 0; i < work.length; i++) {
      const t = work[i]!;
      if (signal.aborted) {
        skipRest(work.slice(i), 'cancelled');
        break;
      }
      env.onProgress(`Exporting file ${i + 1} of ${work.length}: ${labelFor(t)}`);
      try {
        await env.ensureAuth();
        const name = await exportOneToDirectory(
          directory,
          t,
          reserved.get(t.file_id)!,
          () => {
            const next = reserver.reserve(desiredNames.get(t.file_id)!);
            reserved.set(t.file_id, next);
            return next;
          },
          env,
        );
        reserved.set(t.file_id, name);
        result.succeeded.push({ fileId: t.file_id, filename: labelFor(t), bundleName: name });
      } catch (err) {
        const reason = signal.aborted ? 'cancelled' : classifyExportError(err);
        if (reason === 'auth_expired' || reason === 'cancelled') {
          skipRest(work.slice(i), reason);
          break;
        }
        failures.push({ fileId: t.file_id, filename: labelFor(t), reason });
      }
    }
    return failures;
  };

  let failures = await runPass(targets);
  if (failures.length > 0 && result.skipped.length === 0 && !signal.aborted) {
    const retry = env.confirm(`${failures.length} export(s) failed. Retry them once?`);
    if (retry) {
      const failedIds = new Set(failures.map((f) => f.fileId));
      failures = await runPass(targets.filter((t) => failedIds.has(t.file_id)));
    }
  }
  result.failed = failures;
  return result;
}

function formatExportSummary(result: ExportBatchResult): string {
  if (result.mode === 'native') {
    const lines = [
      `Export started for ${result.started.length} file(s) in the browser download folder. Skipped: ${result.skipped.length}.`,
      'Bundles are named <file_id>.arkbackup on this path; decryption restores the original names.',
    ];
    return lines.join('\n');
  }
  const lines = [
    `Export finished. Succeeded: ${result.succeeded.length}. Failed: ${result.failed.length}. Skipped: ${result.skipped.length}.`,
  ];
  for (const f of [...result.failed, ...result.skipped]) {
    lines.push(`  [X] ${f.filename}: ${f.reason || 'failed'}`);
  }
  return lines.join('\n');
}

/**
 * Export the selected vault files. Must be called directly from the click
 * handler so the directory picker opens under the user gesture.
 */
export async function exportSelectedFiles(entries: readonly ExportBatchTarget[]): Promise<ExportBatchResult> {
  if (entries.length === 0) {
    showError('No files selected for export.');
    return { mode: 'cancelled', succeeded: [], failed: [], skipped: [], started: [] };
  }
  const abortController = new AbortController();
  let progressShown = false;
  const env: ExportBatchEnvironment = {
    pickDirectory: pickDirectoryWithBrowser,
    fetchExport: fetchExportResponse,
    triggerNative: triggerNativeExportDownload,
    ensureAuth: ensureFreshBatchAuth,
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    confirm: (message) => window.confirm(message),
    onProgress: (message) => {
      if (!progressShown) {
        progressShown = true;
        showProgress({
          title: 'Exporting encrypted backups',
          message,
          indeterminate: true,
          allowCancel: true,
          onCancel: () => abortController.abort(),
        });
        return;
      }
      updateProgress({ message });
    },
    abortController,
  };

  if (!directoryPickerAvailable() && entries.length > 1) {
    showWarning(
      'Your browser cannot choose a folder, so each bundle starts as a separate download. ' +
        'The browser may ask permission to download multiple files.',
    );
  }

  const result = await runExportBatch(entries, env);
  if (progressShown) {
    hideProgress();
  }
  if (result.mode === 'cancelled') {
    return result;
  }
  const summary = formatExportSummary(result);
  if (result.failed.length > 0 || result.skipped.length > 0) {
    showWarning(summary);
  } else {
    showSuccess(summary);
  }
  return result;
}
