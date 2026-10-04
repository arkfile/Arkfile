/**
 * Unit Tests -- Export selected (export-batch.ts) and directory publishing.
 */

import './setup';
import { describe, test, expect, afterEach } from 'bun:test';
import { runExportBatch, type ExportBatchEnvironment, type ExportBatchTarget } from '../files/export-batch';
import { writeToDirectoryEntry } from '../files/directory-publish';

function namedError(name: string): Error {
  return Object.assign(new Error(name), { name });
}

class FakeFileHandle {
  readonly kind = 'file';
  constructor(
    private readonly dir: FakeDirectory,
    public name: string,
  ) {}

  async createWritable(): Promise<WritableStream<Uint8Array>> {
    const chunks: Uint8Array[] = [];
    const dir = this.dir;
    const handle = this;
    return new WritableStream<Uint8Array>({
      write(chunk) {
        chunks.push(chunk);
      },
      close() {
        const total = chunks.reduce((n, c) => n + c.byteLength, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const c of chunks) {
          out.set(c, offset);
          offset += c.byteLength;
        }
        dir.files.set(handle.name, out);
      },
    });
  }

  async move(newName: string): Promise<void> {
    this.dir.beforeMove?.(newName);
    const data = this.dir.files.get(this.name) ?? new Uint8Array();
    this.dir.files.delete(this.name);
    this.dir.files.set(newName, data);
    this.name = newName;
  }
}

class FakeDirectory {
  files = new Map<string, Uint8Array>();
  dirs = new Set<string>();
  created: string[] = [];
  removed: string[] = [];
  beforeMove?: (name: string) => void;

  async getFileHandle(name: string, opts?: { create?: boolean }): Promise<FakeFileHandle> {
    if (this.dirs.has(name)) throw namedError('TypeMismatchError');
    if (!this.files.has(name)) {
      if (!opts?.create) throw namedError('NotFoundError');
      this.files.set(name, new Uint8Array());
      this.created.push(name);
    }
    return new FakeFileHandle(this, name);
  }

  async getDirectoryHandle(name: string): Promise<object> {
    if (this.dirs.has(name)) return {};
    throw namedError('NotFoundError');
  }

  async removeEntry(name: string): Promise<void> {
    this.files.delete(name);
    this.removed.push(name);
  }

  async *keys(): AsyncIterableIterator<string> {
    for (const name of [...this.files.keys(), ...this.dirs]) yield name;
  }
}

const encoder = new TextEncoder();
const bundleBytes = (id: string) => encoder.encode(`ARKB-bundle-for-${id}`);

function bundleResponse(id: string, opts: { status?: number; declaredLength?: number } = {}): Response {
  const body = bundleBytes(id);
  const headers = new Headers({ 'Content-Length': String(opts.declaredLength ?? body.byteLength) });
  return new Response(new Blob([body]).stream(), { status: opts.status ?? 200, headers });
}

interface EnvLog {
  fetched: string[];
  native: string[];
  sleeps: number;
  confirms: string[];
}

function makeEnv(
  overrides: Partial<ExportBatchEnvironment> & { dir?: FakeDirectory | 'unavailable' | 'cancelled' },
  log: EnvLog,
): ExportBatchEnvironment {
  const { dir, ...rest } = overrides;
  return {
    pickDirectory: async () => (dir ?? 'unavailable') as unknown as FileSystemDirectoryHandle,
    fetchExport: async (id) => {
      log.fetched.push(id);
      return bundleResponse(id);
    },
    triggerNative: (id) => {
      log.native.push(id);
    },
    ensureAuth: async () => {},
    sleep: async () => {
      log.sleeps += 1;
    },
    confirm: (message) => {
      log.confirms.push(message);
      return false;
    },
    onProgress: () => {},
    abortController: new AbortController(),
    ...rest,
  };
}

const newLog = (): EnvLog => ({ fetched: [], native: [], sleeps: 0, confirms: [] });
const decode = (b: Uint8Array | undefined) => (b ? new TextDecoder().decode(b) : undefined);

const twoPhotos: ExportBatchTarget[] = [
  { file_id: 'id-a', filename: 'photo.png' },
  { file_id: 'id-b', filename: 'photo.png' },
];

afterEach(() => {
  delete (globalThis as any).FileSystemFileHandle;
});

describe('runExportBatch', () => {
  test('explicit picker cancellation starts no downloads', async () => {
    const log = newLog();
    const result = await runExportBatch(twoPhotos, makeEnv({ dir: 'cancelled' }, log));
    expect(result.mode).toBe('cancelled');
    expect(log.fetched).toEqual([]);
    expect(log.native).toEqual([]);
  });

  test('unavailable picker falls back to paced native downloads reported as started', async () => {
    const log = newLog();
    const targets = [...twoPhotos, { file_id: 'id-c', filename: '' }];
    const result = await runExportBatch(targets, makeEnv({ dir: 'unavailable' }, log));
    expect(result.mode).toBe('native');
    expect(log.native).toEqual(['id-a', 'id-b', 'id-c']);
    expect(log.sleeps).toBe(2);
    expect(log.fetched).toEqual([]);
    expect(result.started.map((s) => s.bundleName)).toEqual(['id-a.arkbackup', 'id-b.arkbackup', 'id-c.arkbackup']);
    expect(result.succeeded).toEqual([]);
  });

  test('directory path reserves readable names, treats existing bundles as taken, and streams', async () => {
    const dir = new FakeDirectory();
    dir.files.set('Photo.png.ARKBACKUP', encoder.encode('old bundle'));
    dir.files.set('photo.png', encoder.encode('plaintext, not a bundle'));
    const log = newLog();
    const result = await runExportBatch(twoPhotos, makeEnv({ dir }, log));
    expect(result.mode).toBe('directory');
    expect(result.succeeded.map((s) => s.bundleName)).toEqual(['photo-1.png.arkbackup', 'photo-2.png.arkbackup']);
    expect(decode(dir.files.get('Photo.png.ARKBACKUP'))).toBe('old bundle');
    expect(decode(dir.files.get('photo-1.png.arkbackup'))).toBe('ARKB-bundle-for-id-a');
    expect(decode(dir.files.get('photo-2.png.arkbackup'))).toBe('ARKB-bundle-for-id-b');
    expect(log.fetched).toEqual(['id-a', 'id-b']);
  });

  test('falls back to <file_id>.arkbackup when metadata did not decrypt', async () => {
    const dir = new FakeDirectory();
    const result = await runExportBatch([{ file_id: 'id-x', filename: '' }], makeEnv({ dir }, newLog()));
    expect(result.succeeded[0]!.bundleName).toBe('id-x.arkbackup');
  });

  test('non-OK status and short bodies fail only that file and clean only its own entry', async () => {
    const dir = new FakeDirectory();
    dir.files.set('keep.txt', encoder.encode('unrelated'));
    const log = newLog();
    const targets: ExportBatchTarget[] = [
      { file_id: 'id-404', filename: 'gone.bin' },
      { file_id: 'id-short', filename: 'short.bin' },
      { file_id: 'id-ok', filename: 'ok.bin' },
    ];
    const result = await runExportBatch(
      targets,
      makeEnv(
        {
          dir,
          fetchExport: async (id) => {
            log.fetched.push(id);
            if (id === 'id-404') return bundleResponse(id, { status: 404 });
            if (id === 'id-short') return bundleResponse(id, { declaredLength: 9999 });
            return bundleResponse(id);
          },
        },
        log,
      ),
    );
    expect(result.failed.map((f) => [f.fileId, f.reason])).toEqual([
      ['id-404', 'http_404'],
      ['id-short', 'truncated_bundle'],
    ]);
    expect(result.succeeded.map((s) => s.bundleName)).toEqual(['ok.bin.arkbackup']);
    expect([...dir.files.keys()].sort()).toEqual(['keep.txt', 'ok.bin.arkbackup']);
    expect(dir.removed).toEqual(['short.bin.arkbackup']);
    expect(log.confirms.length).toBe(1);
  });

  test('a response that is not a bundle is rejected', async () => {
    const dir = new FakeDirectory();
    const result = await runExportBatch(
      [{ file_id: 'id-html', filename: 'x' }],
      makeEnv({ dir, fetchExport: async () => new Response('<html>login</html>') }, newLog()),
    );
    expect(result.failed[0]!.reason).toBe('invalid_bundle');
    expect(dir.files.size).toBe(0);
  });

  test('a late destination collision is never replaced (move path)', async () => {
    (globalThis as any).FileSystemFileHandle = class {
      move() {}
    };
    const dir = new FakeDirectory();
    const log = newLog();
    const result = await runExportBatch(
      [{ file_id: 'id-a', filename: 'photo.png' }],
      makeEnv(
        {
          dir,
          fetchExport: async (id) => {
            dir.files.set('photo.png.arkbackup', encoder.encode('appeared later'));
            return bundleResponse(id);
          },
        },
        log,
      ),
    );
    expect(result.succeeded[0]!.bundleName).toBe('photo-1.png.arkbackup');
    expect(decode(dir.files.get('photo.png.arkbackup'))).toBe('appeared later');
    expect([...dir.files.keys()].some((n) => n.endsWith('.tmp'))).toBe(false);
  });

  test('a late destination collision is never replaced (no move support)', async () => {
    const dir = new FakeDirectory();
    const result = await runExportBatch(
      [{ file_id: 'id-a', filename: 'photo.png' }],
      makeEnv(
        {
          dir,
          fetchExport: async (id) => {
            dir.files.set('photo.png.arkbackup', encoder.encode('appeared later'));
            return bundleResponse(id);
          },
        },
        newLog(),
      ),
    );
    expect(result.succeeded[0]!.bundleName).toBe('photo-1.png.arkbackup');
    expect(decode(dir.files.get('photo.png.arkbackup'))).toBe('appeared later');
  });

  test('retry reuses the original reservation', async () => {
    const dir = new FakeDirectory();
    let failOnce = true;
    const log = newLog();
    const result = await runExportBatch(
      twoPhotos,
      makeEnv(
        {
          dir,
          confirm: () => true,
          fetchExport: async (id) => {
            log.fetched.push(id);
            if (id === 'id-a' && failOnce) {
              failOnce = false;
              return bundleResponse(id, { status: 500 });
            }
            return bundleResponse(id);
          },
        },
        log,
      ),
    );
    expect(result.failed).toEqual([]);
    expect(decode(dir.files.get('photo.png.arkbackup'))).toBe('ARKB-bundle-for-id-a');
    expect(decode(dir.files.get('photo-1.png.arkbackup'))).toBe('ARKB-bundle-for-id-b');
    expect(log.fetched).toEqual(['id-a', 'id-b', 'id-a']);
  });

  test('abort stops the run and skips the remainder', async () => {
    const dir = new FakeDirectory();
    const abortController = new AbortController();
    const result = await runExportBatch(
      [...twoPhotos, { file_id: 'id-c', filename: 'c' }],
      makeEnv(
        {
          dir,
          abortController,
          fetchExport: async (id) => {
            abortController.abort();
            return bundleResponse(id);
          },
        },
        newLog(),
      ),
    );
    expect(result.succeeded.length).toBe(0);
    expect(result.skipped.map((s) => s.reason)).toEqual(['cancelled', 'cancelled', 'cancelled']);
    expect(dir.files.size).toBe(0);
  });

  test('session loss skips every remaining file', async () => {
    const dir = new FakeDirectory();
    let calls = 0;
    const result = await runExportBatch(
      [...twoPhotos, { file_id: 'id-c', filename: 'c' }],
      makeEnv(
        {
          dir,
          ensureAuth: async () => {
            calls += 1;
            if (calls === 2) throw new Error('auth_expired');
          },
        },
        newLog(),
      ),
    );
    expect(result.succeeded.length).toBe(1);
    expect(result.skipped.map((s) => [s.fileId, s.reason])).toEqual([
      ['id-b', 'auth_expired'],
      ['id-c', 'auth_expired'],
    ]);
  });

  test('large selections confirm after the folder is chosen and can be declined', async () => {
    const dir = new FakeDirectory();
    const targets = Array.from({ length: 30 }, (_, i) => ({ file_id: `id-${i}`, filename: `f${i}` }));
    const log = newLog();
    const result = await runExportBatch(targets, makeEnv({ dir }, log));
    expect(log.confirms[0]).toContain('larger than the original');
    expect(result.mode).toBe('cancelled');
    expect(log.fetched).toEqual([]);
  });
});

describe('writeToDirectoryEntry cleanup', () => {
  test('failure removes only the entry this attempt created', async () => {
    const dir = new FakeDirectory();
    dir.files.set('report.pdf', encoder.encode('existing'));
    await expect(
      writeToDirectoryEntry(
        dir as unknown as FileSystemDirectoryHandle,
        'report-1.pdf',
        () => 'report-2.pdf',
        async () => {
          throw new Error('integrity_mismatch');
        },
      ),
    ).rejects.toThrow('integrity_mismatch');
    expect(dir.removed).toEqual(['report-1.pdf']);
    expect(decode(dir.files.get('report.pdf'))).toBe('existing');
  });

  test('a reserved name that already exists is never opened for writing', async () => {
    const dir = new FakeDirectory();
    dir.files.set('report.pdf', encoder.encode('existing'));
    await expect(
      writeToDirectoryEntry(
        dir as unknown as FileSystemDirectoryHandle,
        'report.pdf',
        () => {
          throw new Error('destination_exists');
        },
        async () => {},
      ),
    ).rejects.toThrow('destination_exists');
    expect(decode(dir.files.get('report.pdf'))).toBe('existing');
    expect(dir.removed).toEqual([]);
  });
});
