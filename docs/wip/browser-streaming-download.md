# Browser Streaming Download — Large File OOM Fix

## Problem

Downloading files > ~1 GB via the browser UI fails with:

```
Array buffer allocation failed
```

Reported on a 2.1 GB Alma Linux ISO at `test.arkfile.net` (May 2026).

## Root Cause

`streaming-download.ts` collects all decrypted chunks into a `Uint8Array[]` array, then calls `combineChunks()` to produce **one single giant `Uint8Array`** before any bytes are written to disk.

For a 2.1 GB file with 16 MiB chunks (~128 chunks), the JavaScript heap simultaneously holds:

| Object | Size |
|---|---|
| `decryptedChunks[]` array (128 × ~16 MiB) | ~2.1 GB |
| `combineChunks()` output `Uint8Array` | ~2.1 GB |
| Pending encrypted fetch buffers | up to ~2.1 GB |
| Blob for `triggerBrowserDownload` | ~2.1 GB |

**Peak: 4–8 GB in the JS heap.** Chrome's per-context `ArrayBuffer` limit is typically 2–4 GB. Any browser tab on a 32-bit process, older mobile hardware, or a system with limited free RAM will crash with `Array buffer allocation failed`.

The same pattern exists in both:
- `downloadAndDecryptChunks()` (authenticated file downloads)
- `downloadAndDecryptShareChunks()` (public shared file downloads)

## Fix: File System Access API Streaming

Replace the collect-then-save pattern with **write-while-decrypt** using the browser's File System Access API:

```
showSaveFilePicker()  →  createWritable()  →  chunk loop: decrypt, write, free  →  close()
```

Peak memory is bounded to **one chunk at a time (~16 MiB)** instead of the full file.

### Browser support

| Browser | File System Access API | Notes |
|---|---|---|
| Chrome 86+ | ✅ | `showSaveFilePicker` available |
| Edge 86+ | ✅ | Same as Chrome |
| Firefox | ❌ | Not available as of Firefox 126 |
| Safari 15.2+ | Partial | `showSaveFilePicker` available in macOS/iOS |
| Mobile Chrome | ✅ | Android 10+ |

For **Firefox and other unsupported browsers**, fall back to incremental `Blob` construction (chunk-by-chunk `new Blob([existingBlob, newChunk])` approach, which stores data in the browser's internal Blob store rather than JS heap, then trigger `URL.createObjectURL`). This fallback still has the theoretical OOM problem but in practice Blob stores are less heap-constrained and browsers handle them better than giant ArrayBuffers.

## Implementation Plan

### 1. `streaming-download.ts`: new `streamChunksToDisk()` function

```typescript
private async streamChunksToDisk(
  chunks: AsyncIterable<Uint8Array>,
  filename: string
): Promise<{ savedViaFileSystemAPI: boolean; blobUrl?: string }> {
  if ('showSaveFilePicker' in window) {
    const handle = await (window as any).showSaveFilePicker({ suggestedName: filename });
    const writable = await handle.createWritable();
    for await (const chunk of chunks) {
      await writable.write(chunk);
    }
    await writable.close();
    return { savedViaFileSystemAPI: true };
  } else {
    // Firefox fallback: accumulate incrementally into Blob store
    let blob = new Blob([]);
    for await (const chunk of chunks) {
      blob = new Blob([blob, chunk]);
    }
    const url = URL.createObjectURL(blob);
    return { savedViaFileSystemAPI: false, blobUrl: url };
  }
}
```

### 2. Refactor `downloadAndDecryptChunks()` and `downloadAndDecryptShareChunks()`

Convert the chunk loop from accumulate-and-return to yield-per-chunk using an `async generator`:

```typescript
private async *decryptChunksGenerator(
  fileId: string,
  metadata: ChunkedDownloadMetadata,
  fek: Uint8Array,
  isShare: boolean
): AsyncGenerator<Uint8Array> {
  const decryptor = await AESGCMDecryptor.fromRawKey(fek);
  for (let i = 0; i < metadata.total_chunks; i++) {
    const encryptedChunk = await downloadChunkWithRetry(url, headers, ...);
    let chunkData = encryptedChunk;
    if (i === 0) chunkData = encryptedChunk.slice(envelopeHeaderSize);
    const decrypted = await decryptor.decryptChunk(chunkData);
    yield decrypted;
    // encryptedChunk and chunkData are eligible for GC here
  }
}
```

### 3. Update `StreamingDownloadResult` interface

```typescript
export interface StreamingDownloadResult {
  filename: string;
  sha256?: string;
  data?: Uint8Array;           // Present only for legacy fallback path; undefined when savedViaFileSystemAPI=true
  savedViaFileSystemAPI: boolean;
  blobUrl?: string;            // Present only for legacy fallback (Firefox)
}
```

### 4. Update callers

- `download.ts` `downloadFile()`: handle `savedViaFileSystemAPI=true` (no `triggerBrowserDownload` needed)
- `share-access.ts` `downloadFile()`: same
- `triggerBrowserDownload()`: check for `blobUrl` (legacy fallback) vs nothing (FSAPI path saved directly)

### 5. SHA-256 verification

The streaming path must still verify the SHA-256 hash post-download. Two options:
- **Option A**: Hash while decrypting (feed each plaintext chunk to a running `SubtleCrypto.digest` accumulator via a `TransformStream`). Problem: `SubtleCrypto.digest()` is not streaming — must hash the full data at once, which defeats the purpose.
- **Option B (recommended)**: Use the Web Crypto `DigestStream` if available, or compute SHA-256 incrementally using the `@noble/hashes` `sha256.update()` API (already available via the existing crypto primitives), hashing each plaintext chunk as it is written. Final `.digest()` call after all chunks.

### 6. User experience for File System Access path

- The `showSaveFilePicker` dialog appears **before** download starts (user selects destination first)
- Progress bar continues to work (progress is tracked per-chunk as before)
- On success: no additional action needed (file is already on disk)
- On cancel (user dismisses save dialog): throw `DOMException: AbortError` — catch this and show a non-error cancellation message

## Files to Change

| File | Change |
|---|---|
| `client/static/js/src/files/streaming-download.ts` | New generator, new stream-to-disk function, updated result type |
| `client/static/js/src/files/download.ts` | Update to handle new result shape |
| `client/static/js/src/shares/share-access.ts` | Update to handle new result shape |
| `client/static/js/src/__tests__/streaming-download.test.ts` | New test file covering streaming path |

## Non-Goals

- Service Worker streaming: possible but requires significantly more infrastructure (SW registration, message passing) — out of scope for this fix.
- Desktop Electron wrapper: out of scope.
- The `arkfile-client` Go CLI is unaffected and already streams correctly.

## Workaround (immediate)

Users with files > ~1 GB should use:
```
arkfile-client download --file-id <id> --output <path>
```

The CLI uses `io.Reader` streaming through AES-GCM decryption without any memory accumulation.
