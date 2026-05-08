# Browser Streaming Download — Large File Fix

## Problem History

### Phase 1: OOM on > ~1 GB files (fixed)

The original `streaming-download.ts` collected all decrypted chunks into a
`Uint8Array[]` array, then called `combineChunks()` to produce one single giant
`Uint8Array` before any bytes were written to disk. For a 2+ GB file this caused:

```
Array buffer allocation failed
```

This was fixed by switching to incremental Blob construction:
`new Blob([existingBlob, chunk])` per chunk keeps data in the browser's internal
Blob store (off the JS heap), bounding peak heap usage to one chunk (~16 MiB).

### Phase 2: Chromium blob URL ceiling on > ~2 GB files (current fix)

Even with the Blob-based approach, Chromium-based browsers (Brave, Chrome, Edge)
fail to serve blob URLs for Blobs above ~2 GB through the browser download pipeline:

```
check internet connection
```

The symptom is: all chunks download and decrypt successfully, the Blob is fully
assembled, `URL.createObjectURL` succeeds, the `<a download>` anchor is clicked —
but the browser's download manager internally fails to read the blob URL back out
and shows a network error. The Blob data was all there; Chromium's download
infrastructure simply cannot pipe a >2 GB blob URL through its download manager.

## Root Cause (Phase 2)

Chromium's internal download pipeline treats blob URL serving as a network
request. For Blobs above ~2 GB, this internal read fails silently and the download
manager reports a generic network error. This is a Chromium architecture
limitation, not a JavaScript heap issue.

## Fix: File System Access API

The FSAPI `showSaveFilePicker()` + `createWritable()` path writes each decrypted
chunk directly to a `FileSystemWritableFileStream` on disk, bypassing the blob URL
/ download pipeline entirely:

```
showSaveFilePicker() -> createWritable() -> chunk loop: decrypt, write, free -> close()
```

- Peak JS heap: ~1 chunk (~16 MiB) regardless of file size
- No Blob accumulation
- No blob URL
- No 2 GB ceiling
- File appears in the OS file manager as it is being written

## Critical Implementation Constraint

`showSaveFilePicker()` is user-gesture-gated by the browser. It MUST be called
synchronously within a click event handler, before any `await`. If any async
operation (metadata fetch, KDF, network request) occurs before the call, the
browser considers the user gesture expired and blocks the picker from appearing.

The correct pattern used in this codebase:

```typescript
downloadBtn.onclick = () => {
  // showSaveFilePicker() MUST be first — no await before this
  let fsapiHandlePromise: Promise<FileSystemFileHandle> | null = null;
  if ('showSaveFilePicker' in window) {
    fsapiHandlePromise = (window as any).showSaveFilePicker({
      suggestedName: filename,
    }) as Promise<FileSystemFileHandle>;
  }

  // Now call the async download function, passing the Promise
  this.downloadFile(filename, fek, sha256, fsapiHandlePromise);
};
```

The `fsapiHandlePromise` is passed into the async download chain where it is
awaited at the appropriate point (after metadata fetch, KDF, etc.) inside
`streamChunksToDisk()`. This preserves the user gesture association on the
Promise while allowing all async setup to complete before awaiting it.

## Browser Support

| Browser | FSAPI | Behavior |
|---|---|---|
| Brave 86+ | Yes | Save dialog appears immediately on click; chunks stream to disk |
| Chrome 86+ | Yes | Same as Brave |
| Edge 86+ | Yes | Same as Brave |
| Firefox | No | Falls back to incremental Blob path (see below) |
| Safari 15.2+ | Partial | showSaveFilePicker available on macOS/iOS |
| Mobile Chrome (Android 10+) | Yes | Same as desktop Chrome |

## Firefox Fallback

Firefox does not support `showSaveFilePicker` (as of Firefox 126). When
`fsapiHandlePromise` is null/undefined, the streaming manager falls back to
incremental Blob construction: each chunk is appended via
`new Blob([existingBlob, chunk])`.

Firefox's blob URL download pipeline is more permissive than Chromium's and
handles large Blobs (several GB on 64-bit systems) reasonably well. The
theoretical ceiling for Firefox is not hard-documented but community observations
suggest it handles Blobs up to ~4 GB on 64-bit systems with sufficient disk space
for the browser's temporary Blob store.

Firefox users with files > ~4 GB should use the `arkfile-client` CLI tool, which
uses `io.Reader` streaming through AES-GCM decryption with no memory accumulation.

## UX Notes

- On Brave/Chrome: the "Save As" dialog appears immediately when the user clicks
  Download, before any network activity. The user selects the destination first,
  then chunks download and write directly to the chosen file.
- Cancelling the save dialog throws `DOMException: AbortError`. This is caught and
  treated as a neutral cancellation (shown as "Download cancelled." status message,
  not an error).
- On error mid-stream (network failure, disk full, etc.), `writable.abort()` is
  called to release the file handle cleanly.

## Files Changed

| File | Change |
|---|---|
| `client/static/js/src/files/streaming-download.ts` | Added `streamChunksToDisk()` with FSAPI path and Blob fallback; added `fsapiHandlePromise` to `StreamingDownloadOptions`; added `savedViaFileSystemAPI` to `StreamingDownloadResult` |
| `client/static/js/src/shares/share-access.ts` | Calls `showSaveFilePicker()` synchronously on Download button onclick; passes handle Promise to download function |
| `client/static/js/src/files/list.ts` | Same pattern for owner file downloads |
| `client/static/js/src/files/download.ts` | Accepts and forwards `fsapiHandlePromise`; handles FSAPI and Blob result paths |
| `client/static/js/src/__tests__/streaming-download.test.ts` | Tests for FSAPI path, cancellation, write error/abort, and Blob fallback path |

## CLI Workaround (always available)

Users with files > ~4 GB (or any users who prefer not to use the browser UI for
large downloads) should use:

```
arkfile-client download --file-id <id> --output <path>
```

The CLI uses `io.Reader` streaming through AES-GCM decryption without any memory
accumulation and has no browser limitations.
